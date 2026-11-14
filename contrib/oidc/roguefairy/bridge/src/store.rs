// SPDX-FileCopyrightText: 2026 Rogue Fairy Studios
// SPDX-License-Identifier: MIT

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::HashSet;
use std::io::BufWriter;
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::OnceLock;

use lore_base::lore_spawn_blocking_nocontext;
use lore_base::types::Context;
use lore_base::types::RepositoryId;
use parking_lot::RwLock;
use serde::Deserialize;
use serde::Serialize;

use crate::config::StaticProjectConfig;
use crate::config::UserIdField;
use crate::error::StoreError;
use crate::policy::ActionSet;
use crate::policy::CallerClaims;
use crate::policy::ProjectVisibility;
use crate::policy::caller_depends_on_any_project_visibility;
use crate::policy::caller_depends_on_project_visibility;
use crate::policy::granted_action_set_on_project;
use crate::policy::is_valid_project_slug;
use crate::policy::parse_project_repository_name;
use crate::policy::resolve_configured_or_live_visibility;

pub const MAX_REPOSITORIES: usize = 100_000;
pub const MAX_USERS: usize = 100_000;
const PROJECT_VISIBILITY_LIMIT_MULTIPLIER: usize = 4;
const MAX_STATE_FILE_BYTES: u64 = 64 * 1024 * 1024;
const STATE_SCHEMA_VERSION: u32 = 1;

fn max_project_visibilities(max_repositories: usize) -> usize {
    max_repositories.saturating_mul(PROJECT_VISIBILITY_LIMIT_MULTIPLIER)
}

/// Registered repository entry stored by `rfs-lore-bridge`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryRecord {
    pub id: RepositoryId,
    pub name: String,
    pub project: String,
    pub visibility: ProjectVisibility,
    pub creator: String,
    pub created_at: u64,
}

/// Known user entry stored in the user directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRecord {
    pub id: String,
    pub username: String,
    pub display_name: String,
}

#[derive(Clone, Deserialize)]
struct PersistedRepository {
    id: String,
    name: String,
    project: String,
    visibility: ProjectVisibility,
    creator: String,
    created_at: u64,
}

#[derive(Clone, Deserialize)]
struct PersistedUser {
    id: String,
    username: String,
    display_name: String,
    #[serde(default)]
    claim_iat: Option<u64>,
    #[serde(default)]
    refuted_iat: Option<u64>,
}

#[derive(Default, Deserialize)]
struct PersistedState {
    version: u32,
    #[serde(default)]
    repositories: Vec<PersistedRepository>,
    #[serde(default)]
    project_visibilities: BTreeMap<String, ProjectVisibility>,
    #[serde(default)]
    users: Vec<PersistedUser>,
}

fn serialize_repository_id<S: serde::Serializer>(
    id: &RepositoryId,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_str(id)
}

#[derive(Serialize)]
struct PersistedRepositoryRef<'a> {
    #[serde(serialize_with = "serialize_repository_id")]
    id: &'a RepositoryId,
    name: &'a str,
    project: &'a str,
    visibility: ProjectVisibility,
    creator: &'a str,
    created_at: u64,
}

struct PersistedRepositoriesRef<'a>(&'a BTreeMap<RepositoryId, Arc<RepositoryRecord>>);

impl Serialize for PersistedRepositoriesRef<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq as _;
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for rec in self.0.values() {
            seq.serialize_element(&PersistedRepositoryRef {
                id: &rec.id,
                name: &rec.name,
                project: &rec.project,
                visibility: rec.visibility,
                creator: &rec.creator,
                created_at: rec.created_at,
            })?;
        }
        seq.end()
    }
}

#[derive(Serialize)]
struct PersistedUserRef<'a> {
    id: &'a str,
    username: &'a str,
    display_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    claim_iat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refuted_iat: Option<u64>,
}

struct PersistedUsersRef<'a>(&'a UserStoreData);

impl Serialize for PersistedUsersRef<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq as _;
        let mut seq = serializer.serialize_seq(Some(self.0.users.len()))?;
        for user in self.0.users.values() {
            let claim_iat = self
                .0
                .user_claim_iat
                .get(user.id.as_str())
                .copied()
                .filter(|&ts| ts > 0);
            let refuted_iat = self.0.refuted_iat.get(user.id.as_str()).copied();
            seq.serialize_element(&PersistedUserRef {
                id: &user.id,
                username: &user.username,
                display_name: &user.display_name,
                claim_iat,
                refuted_iat,
            })?;
        }
        seq.end()
    }
}

struct PersistedProjectVisibilitiesRef<'a>(&'a BTreeMap<Arc<str>, ProjectVisibility>);

impl Serialize for PersistedProjectVisibilitiesRef<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (project, visibility) in self.0 {
            map.serialize_entry(project.as_ref(), visibility)?;
        }
        map.end()
    }
}

#[derive(Serialize)]
struct RepoFieldsRef<'a> {
    repositories: PersistedRepositoriesRef<'a>,
    project_visibilities: PersistedProjectVisibilitiesRef<'a>,
}

#[derive(Serialize)]
struct UserFieldsRef<'a> {
    users: PersistedUsersRef<'a>,
}

#[derive(Default)]
struct RepoStoreData {
    repositories: BTreeMap<RepositoryId, Arc<RepositoryRecord>>,
    by_name: HashMap<Arc<str>, RepositoryId>,
    project_visibilities: BTreeMap<Arc<str>, ProjectVisibility>,
    active_project_counts: HashMap<Arc<str>, usize>,
    has_internal: bool,
    serialized_fields: OnceLock<Arc<[u8]>>,
}

impl Clone for RepoStoreData {
    fn clone(&self) -> Self {
        Self {
            repositories: self.repositories.clone(),
            by_name: self.by_name.clone(),
            project_visibilities: self.project_visibilities.clone(),
            active_project_counts: self.active_project_counts.clone(),
            has_internal: self.has_internal,
            serialized_fields: OnceLock::new(),
        }
    }
}

impl RepoStoreData {
    fn promote_project_to_restricted(&mut self, project: &str) {
        for repo_arc in self.repositories.values_mut() {
            if repo_arc.project == project && repo_arc.visibility != ProjectVisibility::Restricted {
                Arc::make_mut(repo_arc).visibility = ProjectVisibility::Restricted;
            }
        }
    }

    fn propagate_project_visibilities(&mut self) {
        for repo_arc in self.repositories.values_mut() {
            if let Some(&proj_vis) = self.project_visibilities.get(repo_arc.project.as_str())
                && repo_arc.visibility != proj_vis
            {
                Arc::make_mut(repo_arc).visibility = proj_vis;
            }
        }
    }

    fn increment_project_count(&mut self, project: &str) {
        if let Some(count) = self.active_project_counts.get_mut(project) {
            *count = count.saturating_add(1);
        } else {
            self.active_project_counts.insert(Arc::from(project), 1);
        }
    }

    fn decrement_project_count(&mut self, project: &str) -> bool {
        let Some(count) = self.active_project_counts.get_mut(project) else {
            return false;
        };
        if *count > 1 {
            *count -= 1;
            true
        } else {
            self.active_project_counts.remove(project);
            false
        }
    }

    fn refresh_has_internal(&mut self) {
        self.has_internal = self
            .repositories
            .values()
            .any(|repo| repo.visibility == ProjectVisibility::Internal);
    }

    fn cached_json_fields(&self) -> Result<Arc<[u8]>, serde_json::Error> {
        if let Some(cached) = self.serialized_fields.get() {
            return Ok(Arc::clone(cached));
        }
        let encoded: Arc<[u8]> = Arc::from(serde_json::to_vec(&RepoFieldsRef {
            repositories: PersistedRepositoriesRef(&self.repositories),
            project_visibilities: PersistedProjectVisibilitiesRef(&self.project_visibilities),
        })?);
        let _ = self.serialized_fields.set(Arc::clone(&encoded));
        Ok(encoded)
    }
}

#[derive(Default)]
struct UserStoreData {
    users: BTreeMap<Arc<str>, Arc<UserRecord>>,
    by_username: HashMap<Arc<str>, Arc<str>>,
    username_claim_iat: HashMap<Arc<str>, u64>,
    user_claim_iat: HashMap<Arc<str>, u64>,
    refuted_iat: HashMap<Arc<str>, u64>,
    by_display_name: HashMap<Arc<str>, Arc<BTreeSet<Arc<str>>>>,
    serialized_fields: OnceLock<Arc<[u8]>>,
}

/// Reference-counted snapshot of the in-memory user directory for batch lookups.
pub(crate) struct UsersSnapshot(Arc<UserStoreData>);

impl UsersSnapshot {
    /// Looks up a canonical user ID in this snapshot without cloning the underlying record.
    pub(crate) fn get(&self, canonical_id: &str) -> Option<&UserRecord> {
        self.0.users.get(canonical_id).map(Arc::as_ref)
    }
}

impl Clone for UserStoreData {
    fn clone(&self) -> Self {
        Self {
            users: self.users.clone(),
            by_username: self.by_username.clone(),
            username_claim_iat: self.username_claim_iat.clone(),
            user_claim_iat: self.user_claim_iat.clone(),
            refuted_iat: self.refuted_iat.clone(),
            by_display_name: self.by_display_name.clone(),
            serialized_fields: OnceLock::new(),
        }
    }
}

impl UserStoreData {
    fn record_refuted_iat(&mut self, canonical_id: &Arc<str>, iat: u64) {
        if !self.users.contains_key(canonical_id.as_ref()) {
            return;
        }
        let next = self
            .refuted_iat
            .get(canonical_id.as_ref())
            .copied()
            .map_or(iat, |prev| prev.max(iat));
        self.refuted_iat.insert(Arc::clone(canonical_id), next);
    }

    fn insert_user(&mut self, user: UserRecord, claim_iat: u64) -> Arc<str> {
        if let Some(prev) = self.users.remove(user.id.as_str()) {
            self.user_claim_iat.remove(prev.id.as_str());
            if !prev.username.is_empty()
                && self
                    .by_username
                    .get(prev.username.as_str())
                    .map(Arc::as_ref)
                    == Some(prev.id.as_str())
            {
                self.by_username.remove(prev.username.as_str());
                self.username_claim_iat.remove(prev.username.as_str());
            }
            if !prev.display_name.is_empty()
                && let Some(ids_arc) = self.by_display_name.get_mut(prev.display_name.as_str())
            {
                let ids = Arc::make_mut(ids_arc);
                ids.remove(prev.id.as_str());
                if ids.is_empty() {
                    self.by_display_name.remove(prev.display_name.as_str());
                }
            }
        }

        let id_arc: Arc<str> = Arc::from(user.id.as_str());
        if !user.username.is_empty() {
            let username_arc: Arc<str> = Arc::from(user.username.as_str());
            if let Some(displaced_id) = self
                .by_username
                .insert(Arc::clone(&username_arc), Arc::clone(&id_arc))
                && displaced_id.as_ref() != user.id.as_str()
                && let Some(displaced_user) = self.users.get_mut(displaced_id.as_ref())
            {
                Arc::make_mut(displaced_user).username.clear();
                self.user_claim_iat.remove(displaced_id.as_ref());
            }
            self.username_claim_iat.insert(username_arc, claim_iat);
            self.user_claim_iat.insert(Arc::clone(&id_arc), claim_iat);
        }
        if !user.display_name.is_empty() {
            if let Some(ids_arc) = self.by_display_name.get_mut(user.display_name.as_str()) {
                Arc::make_mut(ids_arc).insert(Arc::clone(&id_arc));
            } else {
                let mut ids = BTreeSet::new();
                ids.insert(Arc::clone(&id_arc));
                self.by_display_name
                    .insert(Arc::from(user.display_name.as_str()), Arc::new(ids));
            }
        }
        self.users.insert(Arc::clone(&id_arc), Arc::new(user));
        id_arc
    }

    fn cached_json_fields(&self) -> Result<Arc<[u8]>, serde_json::Error> {
        if let Some(cached) = self.serialized_fields.get() {
            return Ok(Arc::clone(cached));
        }
        let encoded: Arc<[u8]> = Arc::from(serde_json::to_vec(&UserFieldsRef {
            users: PersistedUsersRef(self),
        })?);
        let _ = self.serialized_fields.set(Arc::clone(&encoded));
        Ok(encoded)
    }
}

#[derive(Clone, Default)]
struct StoreData {
    repos: Arc<RepoStoreData>,
    users: Arc<UserStoreData>,
}

impl StoreData {
    fn from_persisted(
        persisted: PersistedState,
        max_repositories: usize,
        max_users: usize,
        user_id_field: UserIdField,
    ) -> Result<Self, StoreError> {
        if persisted.version != STATE_SCHEMA_VERSION {
            return Err(StoreError::UnsupportedStateVersion {
                version: persisted.version,
            });
        }
        if persisted.repositories.len() > max_repositories {
            return Err(StoreError::CapacityExceeded {
                limit: max_repositories,
            });
        }
        let max_projects = max_project_visibilities(max_repositories);
        if persisted.project_visibilities.len() > max_projects {
            return Err(StoreError::CapacityExceeded {
                limit: max_projects,
            });
        }

        let mut project_visibilities: BTreeMap<Arc<str>, ProjectVisibility> = BTreeMap::new();
        for (slug, vis) in persisted.project_visibilities {
            if !is_valid_project_slug(&slug) {
                return Err(StoreError::InvalidPersistedRepository {
                    id: slug.clone(),
                    reason: format!("invalid project slug '{slug}' in project_visibilities"),
                });
            }
            project_visibilities.insert(Arc::from(slug), vis);
        }

        let mut repos = RepoStoreData {
            repositories: BTreeMap::new(),
            by_name: HashMap::with_capacity(persisted.repositories.len()),
            project_visibilities,
            active_project_counts: HashMap::new(),
            has_internal: false,
            serialized_fields: OnceLock::new(),
        };
        let mut users = UserStoreData::default();

        for item in persisted.repositories {
            let ctx = Context::from_str(&item.id).map_err(|_err| {
                StoreError::InvalidPersistedRepository {
                    id: item.id.clone(),
                    reason: "repository id is not 32 lowercase hex characters".to_owned(),
                }
            })?;
            if ctx.is_zero() {
                return Err(StoreError::InvalidPersistedRepository {
                    id: item.id,
                    reason: "repository id must not be all zeros".to_owned(),
                });
            }
            let parsed_name = parse_project_repository_name(&item.name).map_err(|err| {
                StoreError::InvalidPersistedRepository {
                    id: item.id.clone(),
                    reason: err.to_string(),
                }
            })?;
            if parsed_name.project != item.project {
                return Err(StoreError::InvalidPersistedRepository {
                    id: item.id,
                    reason: format!(
                        "persisted project '{}' disagrees with repository name '{}'",
                        item.project, item.name
                    ),
                });
            }

            let id = RepositoryId::from(ctx);
            if let Some(existing) = repos.repositories.get(&id) {
                return Err(StoreError::RepositoryIdConflict {
                    id: id.to_string(),
                    existing_name: existing.name.clone(),
                });
            }
            if repos.by_name.contains_key(item.name.as_str()) {
                return Err(StoreError::RepositoryNameConflict { name: item.name });
            }
            let visibility = repos
                .project_visibilities
                .get(item.project.as_str())
                .copied()
                .unwrap_or(item.visibility)
                .merge(item.visibility);
            if !crate::jwks::is_valid_directory_query(&item.creator, crate::jwks::MAX_USER_ID_BYTES)
            {
                return Err(StoreError::InvalidPersistedRepository {
                    id: item.id,
                    reason: "persisted creator is empty, oversized, or contains control characters"
                        .to_owned(),
                });
            }
            let creator = match user_id_field {
                UserIdField::Username => item.creator,
                UserIdField::Uuid => match crate::jwks::canonicalize_uuid(&item.creator) {
                    Some(Cow::Borrowed(_)) => item.creator,
                    Some(Cow::Owned(canonical)) => canonical,
                    None => {
                        return Err(StoreError::InvalidPersistedRepository {
                            id: item.id,
                            reason:
                                "persisted creator is not a valid UUID for user_id_field = 'uuid'"
                                    .to_owned(),
                        });
                    }
                },
            };
            repos
                .project_visibilities
                .insert(Arc::from(item.project.as_str()), visibility);
            repos.increment_project_count(&item.project);
            repos.by_name.insert(Arc::from(item.name.as_str()), id);
            repos.repositories.insert(
                id,
                Arc::new(RepositoryRecord {
                    id,
                    name: item.name,
                    project: item.project,
                    visibility,
                    creator,
                    created_at: item.created_at,
                }),
            );
        }

        if repos.project_visibilities.len() > max_projects {
            return Err(StoreError::CapacityExceeded {
                limit: max_projects,
            });
        }

        repos.propagate_project_visibilities();
        repos.refresh_has_internal();

        let max_persisted_iat = crate::http::unix_timestamp_secs()
            .saturating_add(crate::jwks::JWT_CLOCK_SKEW_LEEWAY_SECS)
            .min(u64::MAX - 1);
        for persisted_user in persisted.users {
            let raw_claim_iat = persisted_user.claim_iat;
            let raw_refuted_iat = persisted_user.refuted_iat;
            let mut user = UserRecord {
                id: persisted_user.id,
                username: persisted_user.username,
                display_name: persisted_user.display_name,
            };
            let Some(canonical_id) = normalize_user_id_for_field(&user.id, user_id_field) else {
                continue;
            };
            if let Cow::Owned(normalized) = canonical_id {
                user.id = normalized;
            }
            if !users.users.contains_key(user.id.as_str()) && users.users.len() >= max_users {
                return Err(StoreError::CapacityExceeded { limit: max_users });
            }
            match user_id_field {
                UserIdField::Username => {
                    if user.username != user.id {
                        user.username.clone_from(&user.id);
                    }
                }
                UserIdField::Uuid => {
                    if !crate::jwks::is_valid_directory_query(
                        &user.username,
                        crate::jwks::MAX_USERNAME_BYTES,
                    ) {
                        user.username.clear();
                    }
                }
            }
            if !crate::jwks::is_valid_directory_query(
                &user.display_name,
                crate::jwks::MAX_DISPLAY_NAME_BYTES,
            ) {
                user.display_name = if !user.username.is_empty() {
                    user.username.clone()
                } else {
                    user.id.clone()
                };
            }
            let claim_iat = match user_id_field {
                UserIdField::Username => u64::MAX,
                UserIdField::Uuid => match raw_claim_iat {
                    _ if user.username.is_empty() => 0,
                    Some(u64::MAX) => u64::MAX,
                    Some(ts) => ts.min(max_persisted_iat),
                    None => 0,
                },
            };
            let id_arc = users.insert_user(user, claim_iat);
            if user_id_field == UserIdField::Uuid
                && let Some(refuted) = raw_refuted_iat
            {
                users.record_refuted_iat(&id_arc, refuted.min(max_persisted_iat));
            }
        }

        Ok(Self {
            repos: Arc::new(repos),
            users: Arc::new(users),
        })
    }
}

#[derive(Clone, Copy)]
enum SnapshotPayload<'a> {
    Combined {
        repos: &'a RepoStoreData,
        users: &'a UserStoreData,
    },
    ReposOnly(&'a RepoStoreData),
    UsersOnly(&'a UserStoreData),
}

/// Thread-safe, bounded, atomic file-backed state store for repositories and users.
pub struct BridgeStore {
    data: Arc<RwLock<StoreData>>,
    repo_write_gate: Arc<tokio::sync::Mutex<()>>,
    user_write_gate: Arc<tokio::sync::Mutex<()>>,
    state_path: Option<PathBuf>,
    user_state_path: Option<PathBuf>,
    max_repositories: usize,
    max_users: usize,
    user_id_field: UserIdField,
}

impl BridgeStore {
    /// Opens an existing state file or initializes an empty store at `state_path` with [`UserIdField::Username`].
    pub fn open(state_path: Option<PathBuf>) -> Result<Self, StoreError> {
        Self::open_with_user_id_field(state_path, UserIdField::Username)
    }

    /// Opens an existing state file or initializes an empty store at `state_path` with `user_id_field`.
    pub fn open_with_user_id_field(
        state_path: Option<PathBuf>,
        user_id_field: UserIdField,
    ) -> Result<Self, StoreError> {
        Self::open_with_paths_and_field(state_path, None, user_id_field)
    }

    /// Opens a store persisting repositories at `state_path` and users at `user_state_path` (or inside `state_path` when `None`).
    pub fn open_with_paths_and_field(
        state_path: Option<PathBuf>,
        user_state_path: Option<PathBuf>,
        user_id_field: UserIdField,
    ) -> Result<Self, StoreError> {
        Self::open_with_paths_limits_and_field(
            state_path,
            user_state_path,
            MAX_REPOSITORIES,
            MAX_USERS,
            user_id_field,
        )
    }

    fn open_with_paths_limits_and_field(
        state_path: Option<PathBuf>,
        user_state_path: Option<PathBuf>,
        max_repositories: usize,
        max_users: usize,
        user_id_field: UserIdField,
    ) -> Result<Self, StoreError> {
        let distinct_user_path =
            user_state_path.filter(|u| !state_path.as_ref().is_some_and(|s| same_state_file(s, u)));
        let primary_persisted = match &state_path {
            Some(path) => read_persisted_file(path)?,
            None => None,
        };
        let separate_user_persisted = match &distinct_user_path {
            Some(path) => read_persisted_file(path)?,
            None => None,
        };

        let separate_user_missing = separate_user_persisted.is_none();
        let combined_persisted = match (primary_persisted, separate_user_persisted) {
            (Some(mut primary), Some(user_only)) => {
                primary.users = user_only.users;
                Some(primary)
            }
            (Some(primary), None) => Some(primary),
            (None, Some(user_only)) => Some(PersistedState {
                version: user_only.version,
                repositories: Vec::new(),
                project_visibilities: BTreeMap::new(),
                users: user_only.users,
            }),
            (None, None) => None,
        };

        let data = match combined_persisted {
            Some(persisted) => {
                StoreData::from_persisted(persisted, max_repositories, max_users, user_id_field)?
            }
            None => StoreData::default(),
        };

        if separate_user_missing
            && !data.users.users.is_empty()
            && let Some(ref user_path) = distinct_user_path
        {
            persist_snapshot_blocking(user_path, SnapshotPayload::UsersOnly(&data.users))?;
        }

        let repo_write_gate = Arc::new(tokio::sync::Mutex::new(()));
        let user_write_gate = if distinct_user_path.is_some() {
            Arc::new(tokio::sync::Mutex::new(()))
        } else {
            Arc::clone(&repo_write_gate)
        };

        Ok(Self {
            data: Arc::new(RwLock::new(data)),
            repo_write_gate,
            user_write_gate,
            state_path,
            user_state_path: distinct_user_path,
            max_repositories,
            max_users,
            user_id_field,
        })
    }

    /// Normalizes a requested user ID to its canonical store lookup key, or returns `None` when invalid.
    pub(crate) fn canonical_lookup_key<'a>(&self, raw_id: &'a str) -> Option<Cow<'a, str>> {
        normalize_user_id_for_field(raw_id, self.user_id_field)
    }

    /// Returns whether `id` is currently registered.
    pub fn contains_repository(&self, id: RepositoryId) -> bool {
        self.data.read().repos.repositories.contains_key(&id)
    }

    /// Returns whether at least one registered repository carries [`ProjectVisibility::Internal`].
    pub fn has_internal_repository(&self) -> bool {
        self.data.read().repos.has_internal
    }

    /// Returns whether `project` currently has at least one active registered repository.
    pub fn has_active_repository_in_project(&self, project: &str) -> bool {
        self.data
            .read()
            .repos
            .active_project_counts
            .contains_key(project)
    }

    /// Returns whether `caller`'s authorization on any registered repository depends on live
    /// `authentik` project visibility.
    pub fn caller_depends_on_any_repo_visibility(
        &self,
        caller: &CallerClaims,
        static_projects: &BTreeMap<String, StaticProjectConfig>,
    ) -> bool {
        if !caller_depends_on_any_project_visibility(caller) {
            return false;
        }
        let repos = Arc::clone(&self.data.read().repos);
        if !repos.has_internal {
            return false;
        }
        for (project, &count) in &repos.active_project_counts {
            if count == 0 {
                continue;
            }
            let stored = repos
                .project_visibilities
                .get(project.as_ref())
                .copied()
                .unwrap_or(ProjectVisibility::Internal);
            let static_vis = static_projects
                .get(project.as_ref())
                .map_or(ProjectVisibility::Internal, |p| p.visibility);
            if stored != ProjectVisibility::Restricted
                && static_vis != ProjectVisibility::Restricted
                && caller_depends_on_project_visibility(caller, project)
            {
                return true;
            }
        }
        false
    }

    /// Looks up a registered repository by partition `id`.
    pub fn get_repository(&self, id: RepositoryId) -> Option<Arc<RepositoryRecord>> {
        self.data.read().repos.repositories.get(&id).cloned()
    }

    /// Evaluates repository visibility and action grants for `caller` over a snapshot of the store.
    pub fn list_authorized_for_login<T>(
        &self,
        caller: &CallerClaims,
        static_projects: &BTreeMap<String, StaticProjectConfig>,
        authentik_projects: Option<&HashMap<String, ProjectVisibility>>,
        mut map_entry: impl FnMut(RepositoryId, ActionSet) -> T,
    ) -> Vec<T> {
        let repos = Arc::clone(&self.data.read().repos);
        if caller.is_c_level {
            let mut authorized = Vec::with_capacity(repos.repositories.len());
            for &id in repos.repositories.keys() {
                authorized.push(map_entry(id, ActionSet::ALL));
            }
            return authorized;
        }

        let mut authorized = Vec::new();
        let mut project_actions: HashMap<&str, ActionSet> =
            HashMap::with_capacity(repos.project_visibilities.len());
        for repo in repos.repositories.values() {
            let actions = *project_actions
                .entry(repo.project.as_str())
                .or_insert_with(|| {
                    let stored = repos
                        .project_visibilities
                        .get(repo.project.as_str())
                        .copied()
                        .unwrap_or(ProjectVisibility::Internal);
                    let configured = resolve_configured_or_live_visibility(
                        &repo.project,
                        static_projects,
                        authentik_projects,
                    );
                    let claim_vis = caller
                        .projects
                        .get(repo.project.as_str())
                        .map_or(ProjectVisibility::Internal, |grant| grant.visibility);
                    let effective_vis = repo
                        .visibility
                        .merge(stored)
                        .merge(configured)
                        .merge(claim_vis);
                    granted_action_set_on_project(caller, &repo.project, effective_vis)
                });
            if !actions.is_empty() {
                authorized.push(map_entry(repo.id, actions));
            }
        }
        authorized
    }

    /// Returns the stored visibility of `project`, if known.
    pub fn project_visibility(&self, project: &str) -> Option<ProjectVisibility> {
        self.data
            .read()
            .repos
            .project_visibilities
            .get(project)
            .copied()
    }

    /// Registers a repository idempotently, persisting before publishing to readers.
    pub async fn register_repository(
        &self,
        record: RepositoryRecord,
    ) -> Result<Arc<RepositoryRecord>, StoreError> {
        let gate = self.repo_write_gate.clone().lock_owned().await;

        let (next_repos, effective_record) = {
            let current_repos = Arc::clone(&self.data.read().repos);
            if let Some(existing) = current_repos.repositories.get(&record.id) {
                if existing.name != record.name {
                    return Err(StoreError::RepositoryIdConflict {
                        id: record.id.to_string(),
                        existing_name: existing.name.clone(),
                    });
                }
                let prev_proj_vis = current_repos
                    .project_visibilities
                    .get(existing.project.as_str())
                    .copied();
                let merged_vis = existing
                    .visibility
                    .merge(record.visibility)
                    .merge(prev_proj_vis.unwrap_or(ProjectVisibility::Internal));
                if merged_vis == existing.visibility {
                    return Ok(existing.clone());
                }
                let mut repos = (*current_repos).clone();
                repos
                    .project_visibilities
                    .insert(Arc::from(existing.project.as_str()), merged_vis);
                if merged_vis == ProjectVisibility::Restricted
                    && prev_proj_vis != Some(ProjectVisibility::Restricted)
                {
                    repos.promote_project_to_restricted(&existing.project);
                } else if let Some(slot) = repos.repositories.get_mut(&record.id) {
                    Arc::make_mut(slot).visibility = merged_vis;
                }
                repos.refresh_has_internal();
                let updated_rec =
                    repos
                        .repositories
                        .get(&record.id)
                        .cloned()
                        .unwrap_or_else(|| {
                            let mut cloned = (**existing).clone();
                            cloned.visibility = merged_vis;
                            Arc::new(cloned)
                        });
                (Arc::new(repos), updated_rec)
            } else {
                if let Some(existing_id) = current_repos.by_name.get(record.name.as_str())
                    && *existing_id != record.id
                {
                    return Err(StoreError::RepositoryNameConflict { name: record.name });
                }
                if current_repos.repositories.len() >= self.max_repositories {
                    return Err(StoreError::CapacityExceeded {
                        limit: self.max_repositories,
                    });
                }
                let max_projects = max_project_visibilities(self.max_repositories);
                if !current_repos
                    .project_visibilities
                    .contains_key(record.project.as_str())
                    && current_repos.project_visibilities.len() >= max_projects
                {
                    return Err(StoreError::CapacityExceeded {
                        limit: max_projects,
                    });
                }
                let mut repos = (*current_repos).clone();
                let prev_proj_vis = repos
                    .project_visibilities
                    .get(record.project.as_str())
                    .copied();
                let project_vis = prev_proj_vis
                    .unwrap_or(record.visibility)
                    .merge(record.visibility);
                repos
                    .project_visibilities
                    .insert(Arc::from(record.project.as_str()), project_vis);
                if project_vis == ProjectVisibility::Restricted
                    && prev_proj_vis != Some(ProjectVisibility::Restricted)
                {
                    repos.promote_project_to_restricted(&record.project);
                }
                let mut effective = record;
                effective.visibility = project_vis;
                let effective_arc = Arc::new(effective);
                repos.increment_project_count(&effective_arc.project);
                repos
                    .by_name
                    .insert(Arc::from(effective_arc.name.as_str()), effective_arc.id);
                repos
                    .repositories
                    .insert(effective_arc.id, effective_arc.clone());
                repos.refresh_has_internal();
                (Arc::new(repos), effective_arc)
            }
        };

        self.commit_repos(gate, next_repos).await?;
        Ok(effective_record)
    }

    /// Unregisters a repository if present, succeeding when it is absent.
    pub async fn unregister_repository(&self, id: RepositoryId) -> Result<bool, StoreError> {
        let gate = self.repo_write_gate.clone().lock_owned().await;

        let next_repos = {
            let current_repos = Arc::clone(&self.data.read().repos);
            if !current_repos.repositories.contains_key(&id) {
                return Ok(false);
            }
            let mut repos = (*current_repos).clone();
            if let Some(removed) = repos.repositories.remove(&id) {
                repos.by_name.remove(removed.name.as_str());
                let has_remaining_in_project = repos.decrement_project_count(&removed.project);
                if !has_remaining_in_project
                    && repos.project_visibilities.get(removed.project.as_str())
                        == Some(&ProjectVisibility::Internal)
                {
                    repos.project_visibilities.remove(removed.project.as_str());
                }
            }
            repos.refresh_has_internal();
            Arc::new(repos)
        };

        self.commit_repos(gate, next_repos).await?;
        Ok(true)
    }

    /// Reports whether an authenticated UUID caller's `username` requires live verification
    /// against `authentik`: either `username` is indexed to another UUID, or the caller's
    /// directory-confirmed (`u64::MAX`) record carries a different `username`, and `token_iat`
    /// exceeds any refuted watermark for `id`.
    pub fn needs_live_uuid_username_check(
        &self,
        id: &str,
        username: &str,
        token_iat: Option<u64>,
    ) -> bool {
        if self.user_id_field != UserIdField::Uuid
            || !crate::jwks::is_valid_directory_query(username, crate::jwks::MAX_USERNAME_BYTES)
        {
            return false;
        }
        let Some(canonical_id) = self.canonical_lookup_key(id) else {
            return false;
        };
        let max_iat = crate::http::unix_timestamp_secs()
            .saturating_add(crate::jwks::JWT_CLOCK_SKEW_LEEWAY_SECS)
            .min(u64::MAX - 1);
        let caller_iat = token_iat.map_or(0, |ts| ts.min(max_iat));
        let guard = self.data.read();
        if guard
            .users
            .refuted_iat
            .get(canonical_id.as_ref())
            .is_some_and(|&refuted| caller_iat <= refuted)
        {
            return false;
        }
        if guard
            .users
            .by_username
            .get(username)
            .is_some_and(|owner| owner.as_ref() != canonical_id.as_ref())
        {
            return true;
        }
        guard
            .users
            .users
            .get(canonical_id.as_ref())
            .is_some_and(|existing| {
                guard.users.user_claim_iat.get(canonical_id.as_ref()) == Some(&u64::MAX)
                    && existing.username != username
            })
    }

    /// Records an authenticated caller's directory profile without allocating when unchanged,
    /// leaving an existing `username` assignment owned by another canonical user ID intact.
    pub async fn upsert_caller(
        &self,
        id: &str,
        username: &str,
        display_name: &str,
    ) -> Result<(), StoreError> {
        self.upsert_caller_with_iat(id, username, display_name, None)
            .await
    }

    /// Records an authenticated caller's directory profile with optional OIDC `iat` timestamp
    /// so freshly issued UUID tokens can claim reassigned usernames while replayed stale tokens cannot.
    pub async fn upsert_caller_with_iat(
        &self,
        id: &str,
        username: &str,
        display_name: &str,
        token_iat: Option<u64>,
    ) -> Result<(), StoreError> {
        self.upsert_caller_profile(id, username, display_name, token_iat, true, false)
            .await
    }

    /// Records an authenticated caller's directory profile, allowing cross-UUID `iat` username
    /// reassignment only when `allow_iat_takeover` is `true` (pure-OIDC mode without `authentik` API)
    /// and advancing `refuted_iat` when `refute_caller_username` is `true`.
    pub(crate) async fn upsert_caller_profile(
        &self,
        id: &str,
        username: &str,
        display_name: &str,
        token_iat: Option<u64>,
        allow_iat_takeover: bool,
        refute_caller_username: bool,
    ) -> Result<(), StoreError> {
        let Some(canonical_id) = self.canonical_lookup_key(id) else {
            return Ok(());
        };
        let clean_username = match self.user_id_field {
            UserIdField::Username => id,
            UserIdField::Uuid => {
                if crate::jwks::is_valid_directory_query(username, crate::jwks::MAX_USERNAME_BYTES)
                {
                    username
                } else {
                    ""
                }
            }
        };
        let valid_display_name = crate::jwks::is_valid_directory_query(
            display_name,
            crate::jwks::MAX_DISPLAY_NAME_BYTES,
        )
        .then_some(display_name);
        let max_iat = crate::http::unix_timestamp_secs()
            .saturating_add(crate::jwks::JWT_CLOCK_SKEW_LEEWAY_SECS)
            .min(u64::MAX - 1);
        let clamped_iat = token_iat.map(|ts| ts.min(max_iat));

        {
            let guard = self.data.read();
            match plan_caller_profile_step(
                &guard.users,
                canonical_id.as_ref(),
                clean_username,
                valid_display_name,
                self.user_id_field,
                self.max_users,
                clamped_iat,
                allow_iat_takeover,
                refute_caller_username,
            ) {
                CallerProfileStep::NoOp => return Ok(()),
                CallerProfileStep::OverCapacity => {
                    return Err(StoreError::CapacityExceeded {
                        limit: self.max_users,
                    });
                }
                CallerProfileStep::RefuteOnly { .. } | CallerProfileStep::Upsert { .. } => {}
            }
        }

        let gate = self.user_write_gate.clone().lock_owned().await;
        let next_users = {
            let current_users = Arc::clone(&self.data.read().users);
            match plan_caller_profile_step(
                &current_users,
                canonical_id.as_ref(),
                clean_username,
                valid_display_name,
                self.user_id_field,
                self.max_users,
                clamped_iat,
                allow_iat_takeover,
                refute_caller_username,
            ) {
                CallerProfileStep::NoOp => return Ok(()),
                CallerProfileStep::OverCapacity => {
                    return Err(StoreError::CapacityExceeded {
                        limit: self.max_users,
                    });
                }
                CallerProfileStep::RefuteOnly { refuted_iat } => {
                    let mut user_store = (*current_users).clone();
                    let id_arc: Arc<str> = Arc::from(canonical_id.as_ref());
                    user_store.record_refuted_iat(&id_arc, refuted_iat);
                    Arc::new(user_store)
                }
                CallerProfileStep::Upsert {
                    username: effective_username,
                    display_name: effective_display_name,
                    claim_iat,
                    record_refuted_iat,
                } => {
                    let mut user_store = (*current_users).clone();
                    let username = effective_username.to_owned();
                    let display_name = effective_display_name.to_owned();
                    let id_arc = user_store.insert_user(
                        UserRecord {
                            id: canonical_id.into_owned(),
                            username,
                            display_name,
                        },
                        claim_iat,
                    );
                    if let Some(refuted_iat) = record_refuted_iat {
                        user_store.record_refuted_iat(&id_arc, refuted_iat);
                    }
                    Arc::new(user_store)
                }
            }
        };

        self.commit_users(gate, next_users).await
    }

    /// Inserts or updates a single user directory record when its fields changed.
    pub async fn upsert_user(&self, user: UserRecord) -> Result<(), StoreError> {
        self.upsert_users(std::slice::from_ref(&user)).await
    }

    /// Inserts or updates a batch of user directory records in one persistence write.
    pub async fn upsert_users(&self, users: &[UserRecord]) -> Result<(), StoreError> {
        if users.is_empty() {
            return Ok(());
        }
        {
            let current_users = Arc::clone(&self.data.read().users);
            if !check_user_batch_delta(&current_users, users, self.max_users, self.user_id_field)? {
                return Ok(());
            }
        }

        let gate = self.user_write_gate.clone().lock_owned().await;
        let next_users = {
            let current_users = Arc::clone(&self.data.read().users);
            if !check_user_batch_delta(&current_users, users, self.max_users, self.user_id_field)? {
                return Ok(());
            }
            let mut user_store = (*current_users).clone();

            for user in users {
                let Some(canonical_id) = normalize_user_id_for_field(&user.id, self.user_id_field)
                else {
                    continue;
                };
                let (clean_username, clean_display_name) = sanitize_user_fields(
                    canonical_id.as_ref(),
                    &user.username,
                    &user.display_name,
                    self.user_id_field,
                );
                if is_authoritative_user_unchanged(
                    &user_store,
                    canonical_id.as_ref(),
                    clean_username,
                    clean_display_name,
                ) {
                    continue;
                }
                let username = clean_username.to_owned();
                let display_name = clean_display_name.to_owned();
                user_store.insert_user(
                    UserRecord {
                        id: canonical_id.into_owned(),
                        username,
                        display_name,
                    },
                    u64::MAX,
                );
            }
            Arc::new(user_store)
        };

        self.commit_users(gate, next_users).await
    }

    /// Returns a reference-counted snapshot of the cached user directory.
    pub(crate) fn users_snapshot(&self) -> UsersSnapshot {
        UsersSnapshot(Arc::clone(&self.data.read().users))
    }

    /// Reports whether `username` is confirmed by the user directory (`UserIdField::Username`, or
    /// `claim_iat == u64::MAX` in `UserIdField::Uuid` mode).
    pub fn is_username_directory_confirmed(&self, username: &str) -> bool {
        if self.user_id_field == UserIdField::Username {
            return true;
        }
        if username.is_empty() {
            return false;
        }
        self.data.read().users.username_claim_iat.get(username) == Some(&u64::MAX)
    }

    /// Returns `(owner_id, claim_iat)` when `username` is currently indexed to an unconfirmed
    /// UUID caller (`claim_iat < u64::MAX`), or `None` when absent, confirmed, or in `Username` mode.
    pub fn unconfirmed_username_owner(&self, username: &str) -> Option<(Arc<str>, u64)> {
        if self.user_id_field != UserIdField::Uuid || username.is_empty() {
            return None;
        }
        let guard = self.data.read();
        let owner = guard.users.by_username.get(username)?;
        let claim_iat = guard
            .users
            .username_claim_iat
            .get(username)
            .copied()
            .unwrap_or(0);
        (claim_iat != u64::MAX).then(|| (Arc::clone(owner), claim_iat))
    }

    /// Clears an unconfirmed OIDC-seeded `username` mapping when `authentik` confirms no account
    /// owns `username` and `by_username[username]` still points to `expected_owner_id` at
    /// `claim_iat <= max_claim_iat`.
    pub async fn clear_unconfirmed_username(
        &self,
        username: &str,
        expected_owner_id: &str,
        max_claim_iat: u64,
    ) -> Result<(), StoreError> {
        if self.user_id_field != UserIdField::Uuid || username.is_empty() {
            return Ok(());
        }
        let Some(expected_canonical) = self.canonical_lookup_key(expected_owner_id) else {
            return Ok(());
        };
        {
            let guard = self.data.read();
            let matches_target = guard
                .users
                .by_username
                .get(username)
                .is_some_and(|owner| owner.as_ref() == expected_canonical.as_ref())
                && guard
                    .users
                    .username_claim_iat
                    .get(username)
                    .copied()
                    .is_some_and(|iat| iat != u64::MAX && iat <= max_claim_iat);
            if !matches_target {
                return Ok(());
            }
        }

        let gate = self.user_write_gate.clone().lock_owned().await;
        let next_users = {
            let current_users = Arc::clone(&self.data.read().users);
            let Some(owner_id) = current_users.by_username.get(username).cloned() else {
                return Ok(());
            };
            let owner_iat = current_users
                .username_claim_iat
                .get(username)
                .copied()
                .unwrap_or(0);
            if owner_id.as_ref() != expected_canonical.as_ref()
                || owner_iat == u64::MAX
                || owner_iat > max_claim_iat
            {
                return Ok(());
            }
            let mut user_store = (*current_users).clone();
            user_store.by_username.remove(username);
            user_store.username_claim_iat.remove(username);
            user_store.user_claim_iat.remove(owner_id.as_ref());
            if let Some(owner) = user_store.users.get_mut(owner_id.as_ref()) {
                Arc::make_mut(owner).username.clear();
            }
            user_store.record_refuted_iat(&owner_id, owner_iat);
            Arc::new(user_store)
        };

        self.commit_users(gate, next_users).await
    }

    /// Finds the user whose `username` matches `username` exactly via the 1-to-1 secondary index.
    pub fn find_by_username(&self, username: &str) -> Vec<UserRecord> {
        if username.is_empty() {
            return Vec::new();
        }
        let users = Arc::clone(&self.data.read().users);
        let Some(id) = users.by_username.get(username) else {
            return Vec::new();
        };
        match users.users.get(id.as_ref()) {
            Some(u) => vec![(**u).clone()],
            None => Vec::new(),
        }
    }

    /// Finds users whose `display_name` matches `display_name` exactly via the secondary index.
    pub fn find_by_display_name(&self, display_name: &str) -> Vec<UserRecord> {
        if display_name.is_empty() {
            return Vec::new();
        }
        let users = Arc::clone(&self.data.read().users);
        let Some(ids) = users.by_display_name.get(display_name) else {
            return Vec::new();
        };
        ids.iter()
            .filter_map(|id| users.users.get(id.as_ref()).map(|u| (**u).clone()))
            .collect()
    }

    /// Commits `next_repos` to disk and memory while holding `gate` inside the blocking task
    /// so cancelling the outer request future cannot overlap `.tmp` writes or desynchronize memory.
    async fn commit_repos(
        &self,
        gate: tokio::sync::OwnedMutexGuard<()>,
        next_repos: Arc<RepoStoreData>,
    ) -> Result<(), StoreError> {
        let Some(path) = self.state_path.clone() else {
            self.data.write().repos = next_repos;
            drop(gate);
            return Ok(());
        };
        let split_users = self.user_state_path.is_some();
        let combined_users = (!split_users).then(|| Arc::clone(&self.data.read().users));
        let data_slot = self.data.clone();
        let span = tracing::Span::current();
        lore_spawn_blocking_nocontext!(move || {
            let _entered = span.enter();
            let _gate = gate;
            let payload = match &combined_users {
                Some(users) => SnapshotPayload::Combined {
                    repos: &next_repos,
                    users,
                },
                None => SnapshotPayload::ReposOnly(&next_repos),
            };
            persist_snapshot_blocking(&path, payload)?;
            data_slot.write().repos = next_repos;
            Ok(())
        })
        .await
        .map_err(StoreError::PersistenceTaskFailed)?
    }

    /// Commits `next_users` to disk and memory while holding `gate` inside the blocking task.
    async fn commit_users(
        &self,
        gate: tokio::sync::OwnedMutexGuard<()>,
        next_users: Arc<UserStoreData>,
    ) -> Result<(), StoreError> {
        let target_path = self
            .user_state_path
            .clone()
            .or_else(|| self.state_path.clone());
        let Some(path) = target_path else {
            self.data.write().users = next_users;
            drop(gate);
            return Ok(());
        };
        let split_users = self.user_state_path.is_some();
        let combined_repos = (!split_users).then(|| Arc::clone(&self.data.read().repos));
        let data_slot = self.data.clone();
        let span = tracing::Span::current();
        lore_spawn_blocking_nocontext!(move || {
            let _entered = span.enter();
            let _gate = gate;
            let payload = match &combined_repos {
                Some(repos) => SnapshotPayload::Combined {
                    repos,
                    users: &next_users,
                },
                None => SnapshotPayload::UsersOnly(&next_users),
            };
            persist_snapshot_blocking(&path, payload)?;
            data_slot.write().users = next_users;
            Ok(())
        })
        .await
        .map_err(StoreError::PersistenceTaskFailed)?
    }
}

fn read_persisted_file(path: &Path) -> Result<Option<PersistedState>, StoreError> {
    match std::fs::metadata(path) {
        Ok(meta) => {
            if !meta.is_file() {
                return Err(StoreError::ReadState {
                    path: path.to_path_buf(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "state path is not a regular file",
                    ),
                });
            }
            if meta.len() > MAX_STATE_FILE_BYTES {
                return Err(StoreError::StateFileTooLarge {
                    path: path.to_path_buf(),
                    size: meta.len(),
                    max_bytes: MAX_STATE_FILE_BYTES,
                });
            }
            let raw = std::fs::read_to_string(path).map_err(|source| StoreError::ReadState {
                path: path.to_path_buf(),
                source,
            })?;
            let persisted: PersistedState = serde_json::from_str(&raw)?;
            if persisted.version != STATE_SCHEMA_VERSION {
                return Err(StoreError::UnsupportedStateVersion {
                    version: persisted.version,
                });
            }
            Ok(Some(persisted))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(StoreError::ReadState {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn normalize_user_id_for_field(raw_id: &str, field: UserIdField) -> Option<Cow<'_, str>> {
    if !crate::jwks::is_valid_directory_query(raw_id, crate::jwks::MAX_USER_ID_BYTES) {
        return None;
    }
    match field {
        UserIdField::Username => Some(Cow::Borrowed(raw_id)),
        UserIdField::Uuid => crate::jwks::canonicalize_uuid(raw_id),
    }
}

fn sanitize_user_fields<'a>(
    canonical_id: &'a str,
    username: &'a str,
    display_name: &'a str,
    user_id_field: UserIdField,
) -> (&'a str, &'a str) {
    let clean_username = match user_id_field {
        UserIdField::Username => canonical_id,
        UserIdField::Uuid => {
            if crate::jwks::is_valid_directory_query(username, crate::jwks::MAX_USERNAME_BYTES) {
                username
            } else {
                ""
            }
        }
    };
    let clean_display_name =
        if crate::jwks::is_valid_directory_query(display_name, crate::jwks::MAX_DISPLAY_NAME_BYTES)
        {
            display_name
        } else if !clean_username.is_empty() {
            clean_username
        } else {
            canonical_id
        };
    (clean_username, clean_display_name)
}

enum CallerProfileStep<'a> {
    NoOp,
    OverCapacity,
    RefuteOnly {
        refuted_iat: u64,
    },
    Upsert {
        username: &'a str,
        display_name: &'a str,
        claim_iat: u64,
        record_refuted_iat: Option<u64>,
    },
}

#[allow(clippy::too_many_arguments)]
fn plan_caller_profile_step<'a>(
    users: &UserStoreData,
    canonical_id: &'a str,
    clean_username: &'a str,
    valid_display_name: Option<&'a str>,
    user_id_field: UserIdField,
    max_users: usize,
    clamped_iat: Option<u64>,
    allow_iat_takeover: bool,
    refute_caller_username: bool,
) -> CallerProfileStep<'a> {
    let existing = users.users.get(canonical_id);
    if existing.is_none() && users.users.len() >= max_users {
        return CallerProfileStep::OverCapacity;
    }
    let caller_iat = clamped_iat.unwrap_or(0);
    let refutation_needed = refute_caller_username
        && !clean_username.is_empty()
        && !users
            .refuted_iat
            .get(canonical_id)
            .is_some_and(|&ts| ts >= caller_iat);

    if user_id_field == UserIdField::Uuid
        && let Some(ex) = existing
        && !ex.username.is_empty()
        && users.user_claim_iat.get(canonical_id).copied().unwrap_or(0) > caller_iat
    {
        return if refutation_needed {
            CallerProfileStep::RefuteOnly {
                refuted_iat: caller_iat,
            }
        } else {
            CallerProfileStep::NoOp
        };
    }

    let (effective_username, effective_display_name, claim_iat) = if refute_caller_username {
        ("", valid_display_name.unwrap_or(canonical_id), 0)
    } else {
        effective_caller_fields(
            users,
            canonical_id,
            clean_username,
            valid_display_name,
            user_id_field,
            clamped_iat,
            allow_iat_takeover,
        )
    };

    if let Some(ex) = existing {
        let watermark_current = effective_username.is_empty()
            || (users.user_claim_iat.get(canonical_id).copied().unwrap_or(0) >= claim_iat
                && users
                    .username_claim_iat
                    .get(effective_username)
                    .copied()
                    .unwrap_or(0)
                    >= claim_iat);
        if ex.username == effective_username
            && ex.display_name == effective_display_name
            && watermark_current
        {
            return if refutation_needed {
                CallerProfileStep::RefuteOnly {
                    refuted_iat: caller_iat,
                }
            } else {
                CallerProfileStep::NoOp
            };
        }
    }

    CallerProfileStep::Upsert {
        username: effective_username,
        display_name: effective_display_name,
        claim_iat,
        record_refuted_iat: (refute_caller_username && !clean_username.is_empty())
            .then_some(caller_iat),
    }
}

fn effective_caller_fields<'a>(
    users: &UserStoreData,
    canonical_id: &'a str,
    clean_username: &'a str,
    valid_display_name: Option<&'a str>,
    user_id_field: UserIdField,
    token_iat: Option<u64>,
    allow_iat_takeover: bool,
) -> (&'a str, &'a str, u64) {
    let caller_iat = token_iat.unwrap_or(0);
    let (effective_username, claim_iat) = match user_id_field {
        UserIdField::Username => (canonical_id, u64::MAX),
        UserIdField::Uuid => {
            if clean_username.is_empty()
                || users
                    .refuted_iat
                    .get(canonical_id)
                    .is_some_and(|&refuted_iat| caller_iat <= refuted_iat)
            {
                ("", 0)
            } else if let Some(owner) = users.by_username.get(clean_username) {
                let owner_iat = users
                    .username_claim_iat
                    .get(clean_username)
                    .copied()
                    .unwrap_or(u64::MAX);
                if owner.as_ref() == canonical_id {
                    (clean_username, owner_iat.max(caller_iat))
                } else if allow_iat_takeover
                    && let Some(ts) = token_iat
                    && ts > owner_iat
                {
                    (clean_username, ts)
                } else {
                    ("", 0)
                }
            } else {
                (clean_username, caller_iat)
            }
        }
    };
    let effective_display_name = match valid_display_name {
        Some(name) => name,
        None if !effective_username.is_empty() => effective_username,
        None => canonical_id,
    };
    (effective_username, effective_display_name, claim_iat)
}

fn is_authoritative_user_unchanged(
    store: &UserStoreData,
    canonical_id: &str,
    clean_username: &str,
    clean_display_name: &str,
) -> bool {
    let Some(existing) = store.users.get(canonical_id) else {
        return false;
    };
    if existing.username != clean_username || existing.display_name != clean_display_name {
        return false;
    }
    clean_username.is_empty()
        || (store.by_username.get(clean_username).map(Arc::as_ref) == Some(canonical_id)
            && store.username_claim_iat.get(clean_username) == Some(&u64::MAX)
            && store.user_claim_iat.get(canonical_id) == Some(&u64::MAX))
}

fn check_user_batch_delta<'a>(
    existing_store: &UserStoreData,
    incoming: &'a [UserRecord],
    max_users: usize,
    user_id_field: UserIdField,
) -> Result<bool, StoreError> {
    let mut any_changed = false;
    let mut new_distinct = 0_usize;
    let mut seen_new: Option<HashSet<Cow<'a, str>>> = None;

    for user in incoming {
        let Some(canonical_id) = normalize_user_id_for_field(&user.id, user_id_field) else {
            continue;
        };
        let (clean_username, clean_display_name) = sanitize_user_fields(
            canonical_id.as_ref(),
            &user.username,
            &user.display_name,
            user_id_field,
        );
        if is_authoritative_user_unchanged(
            existing_store,
            canonical_id.as_ref(),
            clean_username,
            clean_display_name,
        ) {
            continue;
        }
        any_changed = true;
        if !existing_store.users.contains_key(canonical_id.as_ref())
            && seen_new
                .get_or_insert_with(HashSet::new)
                .insert(canonical_id)
        {
            new_distinct = new_distinct.saturating_add(1);
        }
    }

    if !any_changed {
        return Ok(false);
    }
    if existing_store.users.len().saturating_add(new_distinct) > max_users {
        return Err(StoreError::CapacityExceeded { limit: max_users });
    }
    Ok(true)
}

fn strip_outer_braces(json_object: &[u8]) -> &[u8] {
    json_object
        .strip_prefix(b"{")
        .and_then(|rest| rest.strip_suffix(b"}"))
        .unwrap_or(&[])
}

fn write_snapshot_json(
    writer: &mut impl std::io::Write,
    tmp_path: &Path,
    payload: SnapshotPayload<'_>,
) -> Result<(), StoreError> {
    match payload {
        SnapshotPayload::Combined { repos, users } => {
            let repo_fields = repos.cached_json_fields()?;
            let user_fields = users.cached_json_fields()?;
            write_raw_parts(
                writer,
                &[
                    b"{\"version\":1,",
                    strip_outer_braces(&repo_fields),
                    b",",
                    strip_outer_braces(&user_fields),
                    b"}",
                ],
            )
            .map_err(|source| StoreError::WriteState {
                path: tmp_path.to_path_buf(),
                source,
            })
        }
        SnapshotPayload::ReposOnly(repos) => {
            let repo_fields = repos.cached_json_fields()?;
            write_raw_parts(
                writer,
                &[
                    b"{\"version\":1,",
                    strip_outer_braces(&repo_fields),
                    b",\"users\":[]}",
                ],
            )
            .map_err(|source| StoreError::WriteState {
                path: tmp_path.to_path_buf(),
                source,
            })
        }
        SnapshotPayload::UsersOnly(users) => {
            let user_fields = users.cached_json_fields()?;
            write_raw_parts(
                writer,
                &[b"{\"version\":1,", strip_outer_braces(&user_fields), b"}"],
            )
            .map_err(|source| StoreError::WriteState {
                path: tmp_path.to_path_buf(),
                source,
            })
        }
    }
}

fn write_raw_parts(writer: &mut impl std::io::Write, parts: &[&[u8]]) -> std::io::Result<()> {
    for part in parts {
        writer.write_all(part)?;
    }
    Ok(())
}

fn persist_snapshot_blocking(path: &Path, payload: SnapshotPayload<'_>) -> Result<(), StoreError> {
    #[cfg(feature = "test-util")]
    test_util::maybe_park_persist_write(path);

    write_file_atomic_0600(
        path,
        |failed_path, source| StoreError::WriteState {
            path: failed_path,
            source,
        },
        |file, tmp_path| {
            {
                let mut writer = BufWriter::new(&mut *file);
                write_snapshot_json(&mut writer, tmp_path, payload)?;
                writer.flush().map_err(|source| StoreError::WriteState {
                    path: tmp_path.to_path_buf(),
                    source,
                })?;
            }
            let written_bytes = file
                .metadata()
                .map_err(|source| StoreError::WriteState {
                    path: tmp_path.to_path_buf(),
                    source,
                })?
                .len();
            if written_bytes > MAX_STATE_FILE_BYTES {
                return Err(StoreError::StateFileTooLarge {
                    path: path.to_path_buf(),
                    size: written_bytes,
                    max_bytes: MAX_STATE_FILE_BYTES,
                });
            }
            Ok(())
        },
    )
}

/// Writes a file atomically via a `0600` `.tmp` sibling, `sync_all`, rename, and Unix parent-directory sync.
pub(crate) fn write_file_atomic_0600<E>(
    path: &Path,
    map_io_err: impl Fn(PathBuf, std::io::Error) -> E,
    write_fn: impl FnOnce(&mut std::fs::File, &Path) -> Result<(), E>,
) -> Result<(), E> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|source| map_io_err(path.to_path_buf(), source))?;
    }

    let mut tmp_os = path.as_os_str().to_os_string();
    tmp_os.push(".tmp");
    let tmp_path = PathBuf::from(tmp_os);

    match std::fs::remove_file(&tmp_path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => return Err(map_io_err(tmp_path, source)),
    }

    let write_result = (|| -> Result<(), E> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp_path)
            .map_err(|source| map_io_err(tmp_path.clone(), source))?;
        write_fn(&mut file, &tmp_path)?;
        file.sync_all()
            .map_err(|source| map_io_err(tmp_path.clone(), source))
    })();

    if let Err(err) = write_result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }

    std::fs::rename(&tmp_path, path).map_err(|source| map_io_err(path.to_path_buf(), source))?;

    #[cfg(unix)]
    {
        let dir_path = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let dir = std::fs::File::open(dir_path)
            .map_err(|source| map_io_err(dir_path.to_path_buf(), source))?;
        dir.sync_all()
            .map_err(|source| map_io_err(dir_path.to_path_buf(), source))?;
    }

    Ok(())
}

fn same_state_file(lhs: &Path, rhs: &Path) -> bool {
    if lhs == rhs {
        return true;
    }
    if let (Ok(canon_l), Ok(canon_r)) = (std::fs::canonicalize(lhs), std::fs::canonicalize(rhs)) {
        return canon_l == canon_r;
    }
    normalize_state_path(lhs) == normalize_state_path(rhs)
}

fn normalize_state_path(path: &Path) -> PathBuf {
    use std::path::Component;

    let anchored: Cow<'_, Path> = if path.is_absolute() {
        Cow::Borrowed(path)
    } else if let Ok(cwd) = std::fs::canonicalize(".") {
        Cow::Owned(cwd.join(path))
    } else {
        Cow::Borrowed(path)
    };

    let mut lexical = PathBuf::new();
    let mut leading_parents: usize = 0;
    for comp in anchored.components() {
        match comp {
            Component::CurDir => {}
            Component::Normal(seg) if seg == "." => {}
            Component::ParentDir => {
                if !lexical.pop() && !anchored.is_absolute() {
                    leading_parents += 1;
                }
            }
            Component::Normal(seg) if seg == ".." => {
                if !lexical.pop() && !anchored.is_absolute() {
                    leading_parents += 1;
                }
            }
            other => lexical.push(other.as_os_str()),
        }
    }
    let mut normalized = PathBuf::new();
    for _ in 0..leading_parents {
        normalized.push("..");
    }
    normalized.push(lexical);

    for ancestor in normalized.ancestors().skip(1) {
        if ancestor.as_os_str().is_empty() {
            break;
        }
        if let Ok(canon_ancestor) = std::fs::canonicalize(ancestor)
            && let Ok(suffix) = normalized.strip_prefix(ancestor)
        {
            return canon_ancestor.join(suffix);
        }
    }
    normalized
}

#[cfg(feature = "test-util")]
pub mod test_util {
    use std::collections::HashMap;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::Condvar;
    use std::sync::LazyLock;

    use parking_lot::Mutex;
    use tokio::sync::oneshot;

    use super::BridgeStore;
    use super::StoreError;
    use super::UserIdField;

    impl BridgeStore {
        /// Opens a store with explicit repository and user capacity limits.
        pub fn open_with_limits(
            state_path: Option<PathBuf>,
            max_repositories: usize,
            max_users: usize,
        ) -> Result<Self, StoreError> {
            Self::open_with_paths_limits_and_field(
                state_path,
                None,
                max_repositories,
                max_users,
                UserIdField::Username,
            )
        }
    }

    struct ParkEntry {
        entered_tx: Option<oneshot::Sender<()>>,
        gate: Arc<(std::sync::Mutex<bool>, Condvar)>,
    }

    static ARMED_PARKS: LazyLock<Mutex<HashMap<PathBuf, ParkEntry>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    /// Guard controlling a single armed persistence pause point for a specific state file.
    pub struct PersistPark {
        entered_rx: oneshot::Receiver<()>,
        gate: Arc<(std::sync::Mutex<bool>, Condvar)>,
    }

    impl PersistPark {
        /// Arms a one-shot pause the next time `state_path` enters `persist_snapshot_blocking`.
        pub fn arm(state_path: &Path) -> Self {
            let (entered_tx, entered_rx) = oneshot::channel();
            let gate = Arc::new((std::sync::Mutex::new(false), Condvar::new()));
            ARMED_PARKS.lock().insert(
                state_path.to_path_buf(),
                ParkEntry {
                    entered_tx: Some(entered_tx),
                    gate: gate.clone(),
                },
            );
            Self { entered_rx, gate }
        }

        /// Waits until the blocking persistence task reaches the pause point.
        pub async fn entered(&mut self) {
            let _ = (&mut self.entered_rx).await;
        }

        /// Releases the paused blocking persistence task.
        pub fn release(self) {
            if let Ok(mut released) = self.gate.0.lock() {
                *released = true;
                self.gate.1.notify_all();
            }
        }
    }

    impl Drop for PersistPark {
        fn drop(&mut self) {
            if let Ok(mut released) = self.gate.0.lock() {
                *released = true;
                self.gate.1.notify_all();
            }
        }
    }

    pub(super) fn maybe_park_persist_write(path: &Path) {
        let entry = ARMED_PARKS.lock().remove(path);
        let Some(mut park) = entry else {
            return;
        };
        if let Some(tx) = park.entered_tx.take() {
            let _ = tx.send(());
        }
        if let Ok(mut released) = park.gate.0.lock() {
            while !*released {
                let Ok(next) = park.gate.1.wait(released) else {
                    break;
                };
                released = next;
            }
        }
    }
}

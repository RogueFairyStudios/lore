// SPDX-FileCopyrightText: 2026 Rogue Fairy Studios
// SPDX-License-Identifier: MIT

use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use lore_base::lore_spawn;
use lore_base::types::Context;
use lore_base::types::RepositoryId;
use lore_proto::lore::user::v1::RepositoryListRequest;
use lore_proto::lore::user::v1::RepositoryListResponse;
use lore_proto::lore::user::v1::RepositoryRegisterRequest;
use lore_proto::lore::user::v1::RepositoryRegisterResponse;
use lore_proto::lore::user::v1::RepositoryUnregisterRequest;
use lore_proto::lore::user::v1::RepositoryUnregisterResponse;
use lore_proto::lore::user::v1::User;
use lore_proto::lore::user::v1::UserFindRequest;
use lore_proto::lore::user::v1::UserFindResponse;
use lore_proto::lore::user::v1::UserGetRequest;
use lore_proto::lore::user::v1::UserGetResponse;
use lore_proto::lore::user::v1::repository_registry_service_server::RepositoryRegistryService;
use lore_proto::lore::user::v1::repository_registry_service_server::RepositoryRegistryServiceServer;
use lore_proto::lore::user::v1::user_find_request::Query;
use lore_proto::lore::user::v1::user_service_server::UserService;
use lore_proto::lore::user::v1::user_service_server::UserServiceServer;
use tokio::task::JoinSet;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::metadata::MetadataMap;
use tonic::service::Routes;
use tracing::Instrument as _;
use tracing::info;
use tracing::warn;

use crate::BridgeRuntime;
use crate::correlation_id_from_metadata;
use crate::error::AuthVerifyError;
use crate::error::StoreError;
use crate::http::unix_timestamp_secs;
use crate::jwks::AuthentikDirectoryError;
use crate::jwks::AuthentikProjectLookup;
use crate::policy::CallerClaims;
use crate::policy::ProjectVisibility;
use crate::policy::VerifiedCaller;
use crate::policy::may_access_partition;
use crate::policy::may_create_repository;
use crate::policy::may_unregister_repository;
use crate::policy::parse_project_repository_name;
use crate::policy::resolve_project_visibility;
use crate::store::RepositoryRecord;
use crate::store::UserRecord;

pub const MAX_USER_GET_IDS: usize = 4096;
pub const MAX_USER_GET_UPSTREAM_LOOKUPS: usize = 128;
const MAX_REGISTRY_DECODE_BYTES: usize = 64 * 1024;
const MAX_USER_DECODE_BYTES: usize = 512 * 1024;
pub(crate) const MAX_FALLBACK_CONCURRENCY: usize = 8;
const USER_BATCH_LOOKUP_TIMEOUT: Duration = Duration::from_secs(15);

/// Tonic implementation of `RepositoryRegistryService` and `UserService`.
#[derive(Clone)]
pub struct GrpcBridgeService {
    runtime: Arc<BridgeRuntime>,
}

impl GrpcBridgeService {
    /// Creates a new gRPC service wrapper around `runtime`.
    pub fn new(runtime: Arc<BridgeRuntime>) -> Self {
        Self { runtime }
    }

    /// Converts both gRPC services into an Axum `Router` for single-port HTTP/gRPC multiplexing.
    pub fn into_axum_router(self) -> Router {
        Routes::new(
            RepositoryRegistryServiceServer::new(self.clone())
                .max_decoding_message_size(MAX_REGISTRY_DECODE_BYTES),
        )
        .add_service(UserServiceServer::new(self).max_decoding_message_size(MAX_USER_DECODE_BYTES))
        .into_axum_router()
    }

    /// Converts `UserService` alone into an Axum `Router`, omitting `RepositoryRegistryService`.
    pub fn into_user_axum_router(self) -> Router {
        Routes::new(UserServiceServer::new(self).max_decoding_message_size(MAX_USER_DECODE_BYTES))
            .into_axum_router()
    }

    async fn authenticate_login(&self, metadata: &MetadataMap) -> Result<CallerClaims, Status> {
        let header = authorization_header(metadata)?;
        let bearer =
            crate::jwks::TokenVerifier::extract_bearer(header).map_err(auth_error_to_status)?;
        self.runtime
            .verifier
            .verify_login_token(bearer)
            .await
            .map_err(auth_error_to_status)
    }

    async fn authenticate_any(&self, metadata: &MetadataMap) -> Result<VerifiedCaller, Status> {
        let header = authorization_header(metadata)?;
        let bearer =
            crate::jwks::TokenVerifier::extract_bearer(header).map_err(auth_error_to_status)?;
        self.runtime
            .verifier
            .verify_any_token(bearer)
            .await
            .map_err(auth_error_to_status)
    }

    async fn record_caller_user(&self, caller: &CallerClaims) {
        self.runtime.record_caller_profile(caller).await;
    }

    async fn record_verified_caller_user(&self, caller: &VerifiedCaller) {
        if let VerifiedCaller::Login(login) = caller {
            self.record_caller_user(login).await;
        }
    }

    async fn verify_partition_scope(
        &self,
        caller: &VerifiedCaller,
        raw_partition: &[u8],
    ) -> Result<(), Status> {
        if raw_partition.is_empty() || raw_partition == [0_u8; 16] {
            return match caller {
                VerifiedCaller::Login(login)
                    if login.is_c_level
                        || (login.is_employee && !login.is_partner)
                        || !login.global_actions.is_empty() =>
                {
                    Ok(())
                }
                _ => Err(Status::permission_denied(
                    "caller holds no studio-wide user directory access",
                )),
            };
        }

        let partition_id = parse_repository_id(raw_partition)?;
        if let Some(repo) = self.runtime.store.get_repository(partition_id) {
            let vis = self
                .runtime
                .resolve_verified_caller_repo_visibility(caller, &repo)
                .await
                .map_err(group_directory_error_to_status)?;
            if may_access_partition(caller, &repo, vis) {
                return Ok(());
            }
            return Err(Status::permission_denied(
                "caller is not permitted to query users in this partition",
            ));
        }

        match caller {
            VerifiedCaller::Login(login) if login.is_c_level => Ok(()),
            VerifiedCaller::Login(_) | VerifiedCaller::Exchanged(_) => Err(
                Status::permission_denied("partition is not registered or caller has no access"),
            ),
        }
    }

    async fn repository_list_inner(
        &self,
        request: Request<RepositoryListRequest>,
    ) -> Result<
        Response<tokio_stream::Iter<std::vec::IntoIter<Result<RepositoryListResponse, Status>>>>,
        Status,
    > {
        let (metadata, _extensions, _body) = request.into_parts();
        let caller = self.authenticate_any(&metadata).await?;

        let authorized = match &caller {
            VerifiedCaller::Login(login) => {
                let authentik_projects = if self
                    .runtime
                    .store
                    .caller_depends_on_any_repo_visibility(login, &self.runtime.config.projects)
                    && self.runtime.verifier.has_authentik_api()
                {
                    self.runtime
                        .verifier
                        .refresh_group_visibilities()
                        .await
                        .map_err(group_directory_error_to_status)?
                } else {
                    None
                };
                let items = self.runtime.store.list_authorized_for_login(
                    login,
                    &self.runtime.config.projects,
                    authentik_projects.as_deref(),
                    |id, actions| {
                        Ok(RepositoryListResponse {
                            id: id.into(),
                            permission: actions.to_permission_strings(),
                        })
                    },
                );
                if login_has_any_grant(login, !items.is_empty()) {
                    self.record_caller_user(login).await;
                }
                items
            }
            VerifiedCaller::Exchanged(exchanged) => {
                if !exchanged.actions.is_empty()
                    && self
                        .runtime
                        .store
                        .contains_repository(exchanged.repository_id)
                {
                    vec![Ok(RepositoryListResponse {
                        id: exchanged.repository_id.into(),
                        permission: exchanged.actions.to_permission_strings(),
                    })]
                } else {
                    Vec::new()
                }
            }
        };

        Ok(Response::new(tokio_stream::iter(authorized)))
    }

    async fn repository_register_inner(
        &self,
        request: Request<RepositoryRegisterRequest>,
    ) -> Result<Response<RepositoryRegisterResponse>, Status> {
        let (metadata, _extensions, body) = request.into_parts();
        let caller = self.authenticate_login(&metadata).await?;
        let repository_id = parse_repository_id(&body.id)?;
        let parsed = parse_project_repository_name(&body.name)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;

        if !may_create_repository(&caller, parsed.project) {
            info!(
                identity = %caller.identity,
                project = %parsed.project,
                name = %parsed.full_name,
                "refused RepositoryRegister: caller lacks create permission on project"
            );
            return Err(Status::permission_denied(format!(
                "caller '{}' is not permitted to create repositories in project '{}'",
                caller.identity, parsed.project
            )));
        }

        let stored_vis = self.runtime.store.project_visibility(parsed.project);
        let mut configured_vis = self
            .runtime
            .config
            .projects
            .get(parsed.project)
            .map(|p| p.visibility);
        let caller_in_project = caller
            .projects
            .get(parsed.project)
            .is_some_and(|grant| !grant.actions.is_empty() || grant.can_create_repo);
        let already_registered_same_name = self
            .runtime
            .store
            .get_repository(repository_id)
            .is_some_and(|existing| existing.name == parsed.full_name);

        match configured_vis {
            Some(ProjectVisibility::Internal) => {
                if self.runtime.verifier.has_authentik_api() {
                    match self
                        .runtime
                        .verifier
                        .lookup_authentik_project_visibility(parsed.project)
                        .await
                    {
                        AuthentikProjectLookup::Found(vis) => {
                            configured_vis = Some(ProjectVisibility::Internal.merge(vis));
                        }
                        AuthentikProjectLookup::NotFound
                        | AuthentikProjectLookup::NotConfigured => {}
                        AuthentikProjectLookup::Unavailable => {
                            return Err(Status::unavailable(
                                "authentik group directory is temporarily unavailable",
                            ));
                        }
                    }
                }
            }
            None if !caller_in_project || self.runtime.verifier.has_authentik_api() => {
                match self
                    .runtime
                    .verifier
                    .lookup_authentik_project_visibility(parsed.project)
                    .await
                {
                    AuthentikProjectLookup::Found(vis) => {
                        configured_vis = Some(vis);
                    }
                    AuthentikProjectLookup::NotFound if !already_registered_same_name => {
                        return Err(Status::not_found(format!(
                            "project '{}' is not defined in authentik groups or static [projects] configuration",
                            parsed.project
                        )));
                    }
                    AuthentikProjectLookup::NotConfigured
                        if !caller_in_project
                            && !already_registered_same_name
                            && !self
                                .runtime
                                .store
                                .has_active_repository_in_project(parsed.project) =>
                    {
                        return Err(Status::not_found(format!(
                            "project '{}' is not defined in authentik groups or static [projects] configuration",
                            parsed.project
                        )));
                    }
                    AuthentikProjectLookup::NotFound | AuthentikProjectLookup::NotConfigured => {}
                    AuthentikProjectLookup::Unavailable => {
                        return Err(Status::unavailable(
                            "authentik group directory is temporarily unavailable",
                        ));
                    }
                }
            }
            Some(ProjectVisibility::Restricted) | None => {}
        }

        let visibility =
            resolve_project_visibility(&caller, parsed.project, stored_vis, configured_vis);
        self.record_caller_user(&caller).await;

        let record = RepositoryRecord {
            id: repository_id,
            name: parsed.full_name.to_owned(),
            project: parsed.project.to_owned(),
            visibility,
            creator: caller.identity.clone(),
            created_at: unix_timestamp_secs(),
        };

        match self.runtime.store.register_repository(record).await {
            Ok(_) => {
                info!(
                    identity = %caller.identity,
                    repository = %repository_id,
                    name = %parsed.full_name,
                    project = %parsed.project,
                    ?visibility,
                    "registered project repository"
                );
                Ok(Response::new(RepositoryRegisterResponse {}))
            }
            Err(
                StoreError::RepositoryIdConflict { .. } | StoreError::RepositoryNameConflict { .. },
            ) => Err(Status::already_exists(format!(
                "repository '{}' or id '{}' conflicts with an existing registration",
                parsed.full_name, repository_id
            ))),
            Err(StoreError::CapacityExceeded { limit }) => Err(Status::resource_exhausted(
                format!("repository registry reached limit of {limit}"),
            )),
            Err(StoreError::StateFileTooLarge { max_bytes, .. }) => {
                Err(Status::resource_exhausted(format!(
                    "repository registry state exceeded {max_bytes} bytes"
                )))
            }
            Err(err) => {
                warn!(?err, repository = %repository_id, "failed to persist repository registration");
                Err(Status::internal(
                    "failed to persist repository registration",
                ))
            }
        }
    }

    async fn repository_unregister_inner(
        &self,
        request: Request<RepositoryUnregisterRequest>,
    ) -> Result<Response<RepositoryUnregisterResponse>, Status> {
        let (metadata, _extensions, body) = request.into_parts();
        let caller = self.authenticate_any(&metadata).await?;
        let repository_id = parse_repository_id(&body.id)?;

        let Some(existing) = self.runtime.store.get_repository(repository_id) else {
            return Ok(Response::new(RepositoryUnregisterResponse {}));
        };

        let effective_vis = self
            .runtime
            .resolve_verified_caller_repo_visibility(&caller, &existing)
            .await
            .map_err(group_directory_error_to_status)?;
        if !may_unregister_repository(
            &caller,
            &existing,
            effective_vis,
            self.runtime.config.authentik.user_id_field,
        ) {
            info!(
                identity = %caller.identity(),
                repository = %repository_id,
                name = %existing.name,
                "refused RepositoryUnregister: caller lacks permission"
            );
            return Err(Status::permission_denied(
                "caller is not permitted to unregister this repository",
            ));
        }

        self.record_verified_caller_user(&caller).await;
        self.runtime
            .store
            .unregister_repository(repository_id)
            .await
            .map_err(|err| {
                warn!(?err, repository = %repository_id, "failed to persist repository removal");
                Status::internal("failed to unregister repository")
            })?;

        info!(
            identity = %caller.identity(),
            repository = %repository_id,
            name = %existing.name,
            "unregistered project repository"
        );
        Ok(Response::new(RepositoryUnregisterResponse {}))
    }

    async fn user_get_inner(
        &self,
        request: Request<UserGetRequest>,
    ) -> Result<Response<UserGetResponse>, Status> {
        let (metadata, _extensions, body) = request.into_parts();
        let caller = self.authenticate_any(&metadata).await?;
        if body.id.len() > MAX_USER_GET_IDS {
            return Err(Status::invalid_argument(format!(
                "UserGet accepts at most {MAX_USER_GET_IDS} ids per request"
            )));
        }
        self.verify_partition_scope(&caller, &body.partition)
            .await?;
        self.record_verified_caller_user(&caller).await;

        let has_api = self.runtime.verifier.has_authentik_api();
        let mut snapshot = self.runtime.store.users_snapshot();
        let raw_ids = body.id;
        let mut user = Vec::with_capacity(raw_ids.len());
        let mut missed_requests: Vec<(&str, Cow<'_, str>)> = Vec::new();
        let mut missing: Vec<String> = Vec::new();
        {
            let mut seen_raw: HashSet<&str> = HashSet::with_capacity(raw_ids.len());
            let mut seen_missing: HashSet<String> = HashSet::new();
            for id in &raw_ids {
                if !seen_raw.insert(id.as_str()) {
                    continue;
                }
                let Some(canonical) = self.runtime.store.canonical_lookup_key(id) else {
                    continue;
                };
                if let Some(rec) = snapshot.get(canonical.as_ref()) {
                    user.push(User {
                        id: id.clone(),
                        display_name: rec.display_name.clone(),
                        username: rec.username.clone(),
                    });
                    continue;
                }
                if !has_api {
                    continue;
                }
                if !seen_missing.contains(canonical.as_ref()) {
                    let owned = canonical.as_ref().to_owned();
                    seen_missing.insert(owned.clone());
                    missing.push(owned);
                }
                missed_requests.push((id.as_str(), canonical));
            }
        }

        let mut extra_fetched: HashMap<String, UserRecord> = HashMap::new();
        if !missing.is_empty() && has_api {
            self.runtime
                .verifier
                .retain_not_negatively_cached_user_ids(&mut missing);
            missing.truncate(MAX_USER_GET_UPSTREAM_LOOKUPS);
        }

        if !missing.is_empty() && has_api {
            drop(snapshot);
            let mut partial_fetched: Vec<(usize, UserRecord)> = Vec::new();
            let fallback_result = match tokio::time::timeout(
                USER_BATCH_LOOKUP_TIMEOUT,
                fetch_missing_users_bounded(&self.runtime, missing, &mut partial_fetched),
            )
            .await
            {
                Ok(res) => res,
                Err(_elapsed) => Err(Status::unavailable(
                    "authentik user directory timed out resolving batch",
                )),
            };

            if !partial_fetched.is_empty() {
                partial_fetched.sort_unstable_by_key(|(idx, _)| *idx);
                let fetched: Vec<UserRecord> =
                    partial_fetched.into_iter().map(|(_, rec)| rec).collect();
                if let Err(err) = self.runtime.store.upsert_users(&fetched).await {
                    warn!(?err, "failed to persist fetched authentik users");
                    extra_fetched.reserve(fetched.len());
                    for rec in fetched {
                        extra_fetched.insert(rec.id.clone(), rec);
                    }
                }
            }

            snapshot = self.runtime.store.users_snapshot();
            if let Err(status) = fallback_result {
                let tail_resolved = missed_requests
                    .iter()
                    .filter(|(_, canon)| {
                        snapshot.get(canon.as_ref()).is_some()
                            || extra_fetched.contains_key(canon.as_ref())
                    })
                    .count();
                let resolved_count = user.len() + tail_resolved;
                if resolved_count == 0 {
                    return Err(status);
                }
                warn!(
                    code = ?status.code(),
                    resolved_users = resolved_count,
                    "authentik user directory fallback partially failed; returning resolved users"
                );
            }
        }

        for (raw_id, canon) in missed_requests {
            if let Some(rec) = snapshot
                .get(canon.as_ref())
                .or_else(|| extra_fetched.get(canon.as_ref()))
            {
                user.push(User {
                    id: raw_id.to_owned(),
                    display_name: rec.display_name.clone(),
                    username: rec.username.clone(),
                });
            }
        }
        Ok(Response::new(UserGetResponse { user }))
    }

    async fn user_find_inner(
        &self,
        request: Request<UserFindRequest>,
    ) -> Result<Response<UserFindResponse>, Status> {
        let (metadata, _extensions, body) = request.into_parts();
        let caller = self.authenticate_any(&metadata).await?;
        self.verify_partition_scope(&caller, &body.partition)
            .await?;
        self.record_verified_caller_user(&caller).await;

        let matches = match body.query {
            None => Vec::new(),
            Some(Query::Username(username)) => {
                if !crate::jwks::is_valid_directory_query(
                    &username,
                    crate::jwks::MAX_USERNAME_BYTES,
                ) {
                    Vec::new()
                } else {
                    let local = self.runtime.store.find_by_username(&username);
                    if !self.runtime.verifier.has_authentik_api() {
                        local
                    } else if local.is_empty() {
                        Box::pin(self.fallback_find_by_username(&username)).await?
                    } else if self
                        .runtime
                        .store
                        .is_username_directory_confirmed(&username)
                    {
                        local
                    } else {
                        match Box::pin(self.fallback_find_by_username(&username)).await {
                            Ok(verified) => verified,
                            Err(status) => {
                                warn!(
                                    code = ?status.code(),
                                    %username,
                                    "authentik user directory unavailable while verifying unconfirmed username; returning cached caller"
                                );
                                local
                            }
                        }
                    }
                }
            }
            Some(Query::DisplayName(display_name)) => {
                if !crate::jwks::is_valid_directory_query(
                    &display_name,
                    crate::jwks::MAX_DISPLAY_NAME_BYTES,
                ) {
                    Vec::new()
                } else {
                    let mut local = self.runtime.store.find_by_display_name(&display_name);
                    if local.is_empty() && self.runtime.verifier.has_authentik_api() {
                        local = Box::pin(self.fallback_find_by_display_name(&display_name)).await?;
                    }
                    local
                }
            }
        };

        let user = matches.into_iter().map(to_proto_user).collect();
        Ok(Response::new(UserFindResponse { user }))
    }

    /// Cold cache-miss wrapper acquiring an `upstream_user_semaphore` permit under
    /// `USER_BATCH_LOOKUP_TIMEOUT`. Callers box this path so cache-hit `UserFind` futures stay small.
    async fn run_bounded_user_lookup<T, F>(&self, op: F) -> Result<T, Status>
    where
        F: std::future::Future<Output = Result<T, Status>>,
    {
        tokio::time::timeout(USER_BATCH_LOOKUP_TIMEOUT, async {
            let _permit = self
                .runtime
                .upstream_user_semaphore
                .acquire()
                .await
                .map_err(|_closed| Status::unavailable("user directory shutting down"))?;
            op.await
        })
        .await
        .map_err(|_elapsed| Status::unavailable("authentik user directory timed out"))?
    }

    /// Cold cache-miss or unconfirmed-username verification path querying `authentik` for an exact `username` match.
    async fn fallback_find_by_username(&self, username: &str) -> Result<Vec<UserRecord>, Status> {
        let outcome = self
            .run_bounded_user_lookup(async {
                let recheck = self.runtime.store.find_by_username(username);
                if !recheck.is_empty()
                    && self.runtime.store.is_username_directory_confirmed(username)
                {
                    return Ok(LookupOutcome::Cached(recheck));
                }
                let pre_owner = self.runtime.store.unconfirmed_username_owner(username);
                let lookup_res = if pre_owner.is_some() {
                    self.runtime
                        .verifier
                        .lookup_authentik_user_by_username_live(username)
                        .await
                } else {
                    self.runtime
                        .verifier
                        .lookup_authentik_user_by_username(username)
                        .await
                };
                lookup_res
                    .map(|remote| LookupOutcome::Fetched((remote, pre_owner)))
                    .map_err(user_directory_error_to_status)
            })
            .await?;
        match outcome {
            LookupOutcome::Cached(records) => Ok(records),
            LookupOutcome::Fetched((Some(remote), _pre_owner)) => {
                if let Err(err) = self.runtime.store.upsert_user(remote.clone()).await {
                    warn!(?err, "failed to persist fetched authentik user");
                }
                Ok(vec![remote])
            }
            LookupOutcome::Fetched((None, pre_owner)) => {
                if let Some((owner_id, max_iat)) = pre_owner
                    && let Err(err) = self
                        .runtime
                        .store
                        .clear_unconfirmed_username(username, &owner_id, max_iat)
                        .await
                {
                    warn!(
                        ?err,
                        "failed to clear unconfirmed username after empty authentik lookup"
                    );
                }
                Ok(Vec::new())
            }
        }
    }

    /// Cold cache-miss path querying `authentik` for an exact `display_name` match.
    async fn fallback_find_by_display_name(
        &self,
        display_name: &str,
    ) -> Result<Vec<UserRecord>, Status> {
        let outcome = self
            .run_bounded_user_lookup(async {
                let recheck = self.runtime.store.find_by_display_name(display_name);
                if !recheck.is_empty() {
                    return Ok(LookupOutcome::Cached(recheck));
                }
                self.runtime
                    .verifier
                    .lookup_authentik_users_by_display_name(display_name)
                    .await
                    .map(LookupOutcome::Fetched)
                    .map_err(user_directory_error_to_status)
            })
            .await?;
        match outcome {
            LookupOutcome::Cached(records) => Ok(records),
            LookupOutcome::Fetched(remote_list) => {
                if !remote_list.is_empty()
                    && let Err(err) = self.runtime.store.upsert_users(&remote_list).await
                {
                    warn!(?err, "failed to persist fetched authentik users");
                }
                Ok(remote_list)
            }
        }
    }
}

enum LookupOutcome<T> {
    Cached(Vec<UserRecord>),
    Fetched(T),
}

#[tonic::async_trait]
impl RepositoryRegistryService for GrpcBridgeService {
    type RepositoryListStream =
        tokio_stream::Iter<std::vec::IntoIter<Result<RepositoryListResponse, Status>>>;

    async fn repository_list(
        &self,
        request: Request<RepositoryListRequest>,
    ) -> Result<Response<Self::RepositoryListStream>, Status> {
        let span = tracing::info_span!(
            "repository_list",
            correlation_id = correlation_id_from_metadata(request.metadata()),
        );
        self.repository_list_inner(request).instrument(span).await
    }

    async fn repository_register(
        &self,
        request: Request<RepositoryRegisterRequest>,
    ) -> Result<Response<RepositoryRegisterResponse>, Status> {
        let span = tracing::info_span!(
            "repository_register",
            correlation_id = correlation_id_from_metadata(request.metadata()),
        );
        self.repository_register_inner(request)
            .instrument(span)
            .await
    }

    async fn repository_unregister(
        &self,
        request: Request<RepositoryUnregisterRequest>,
    ) -> Result<Response<RepositoryUnregisterResponse>, Status> {
        let span = tracing::info_span!(
            "repository_unregister",
            correlation_id = correlation_id_from_metadata(request.metadata()),
        );
        self.repository_unregister_inner(request)
            .instrument(span)
            .await
    }
}

#[tonic::async_trait]
impl UserService for GrpcBridgeService {
    async fn user_get(
        &self,
        request: Request<UserGetRequest>,
    ) -> Result<Response<UserGetResponse>, Status> {
        let span = tracing::info_span!(
            "user_get",
            correlation_id = correlation_id_from_metadata(request.metadata()),
        );
        self.user_get_inner(request).instrument(span).await
    }

    async fn user_find(
        &self,
        request: Request<UserFindRequest>,
    ) -> Result<Response<UserFindResponse>, Status> {
        let span = tracing::info_span!(
            "user_find",
            correlation_id = correlation_id_from_metadata(request.metadata()),
        );
        self.user_find_inner(request).instrument(span).await
    }
}

async fn fetch_missing_users_bounded(
    runtime: &Arc<BridgeRuntime>,
    missing: Vec<String>,
    partial_out: &mut Vec<(usize, UserRecord)>,
) -> Result<(), Status> {
    let mut tasks = JoinSet::new();
    let mut iter = missing.into_iter().enumerate();

    for (idx, user_id) in iter.by_ref().take(MAX_FALLBACK_CONCURRENCY) {
        lore_spawn!(
            tasks,
            lookup_single_missing_user(runtime.clone(), idx, user_id).in_current_span()
        );
    }

    let mut first_error: Option<Status> = None;
    loop {
        let Some(joined) = tasks.join_next().await else {
            break;
        };
        match joined {
            Ok(Ok(Some(entry))) => partial_out.push(entry),
            Ok(Ok(None)) => {}
            Ok(Err(err)) => {
                if first_error.is_none() {
                    first_error = Some(user_directory_error_to_status(err));
                }
            }
            Err(err) => {
                warn!(?err, "authentik user lookup task failed");
                if first_error.is_none() {
                    first_error = Some(Status::internal("user directory lookup task failed"));
                }
            }
        }
        if first_error.is_none()
            && let Some((idx, user_id)) = iter.next()
        {
            lore_spawn!(
                tasks,
                lookup_single_missing_user(runtime.clone(), idx, user_id).in_current_span()
            );
        }
    }

    match first_error {
        Some(status) => Err(status),
        None => Ok(()),
    }
}

async fn lookup_single_missing_user(
    runtime: Arc<BridgeRuntime>,
    idx: usize,
    user_id: String,
) -> Result<Option<(usize, UserRecord)>, AuthentikDirectoryError> {
    let _permit = runtime
        .upstream_user_semaphore
        .acquire()
        .await
        .map_err(|_closed| AuthentikDirectoryError::Unavailable)?;
    runtime
        .verifier
        .lookup_authentik_user_by_id(&user_id)
        .await
        .map(|opt| opt.map(|rec| (idx, rec)))
}

fn user_directory_error_to_status(err: AuthentikDirectoryError) -> Status {
    match err {
        AuthentikDirectoryError::Unavailable => {
            Status::unavailable("authentik user directory is temporarily unavailable")
        }
    }
}

fn group_directory_error_to_status(err: AuthentikDirectoryError) -> Status {
    match err {
        AuthentikDirectoryError::Unavailable => {
            Status::unavailable("authentik group directory is temporarily unavailable")
        }
    }
}

fn to_proto_user(record: UserRecord) -> User {
    User {
        id: record.id,
        display_name: record.display_name,
        username: record.username,
    }
}

fn authorization_header(metadata: &MetadataMap) -> Result<Option<&str>, Status> {
    match metadata.get("authorization") {
        Some(value) => value
            .to_str()
            .map(Some)
            .map_err(|_err| Status::unauthenticated("non-ASCII authorization metadata")),
        None => Ok(None),
    }
}

fn auth_error_to_status(err: AuthVerifyError) -> Status {
    match err {
        AuthVerifyError::ProviderUnavailable { .. } => {
            Status::unavailable("identity provider keys are temporarily unavailable")
        }
        AuthVerifyError::MissingBearerToken
        | AuthVerifyError::MalformedAuthorizationHeader
        | AuthVerifyError::TokenTooLarge
        | AuthVerifyError::MalformedToken
        | AuthVerifyError::MissingKeyId
        | AuthVerifyError::IssuerNotAccepted { .. }
        | AuthVerifyError::UnknownSigningKey { .. }
        | AuthVerifyError::InvalidToken
        | AuthVerifyError::MissingIdentity => Status::unauthenticated("unauthenticated"),
    }
}

fn login_has_any_grant(login: &CallerClaims, has_listed_repos: bool) -> bool {
    has_listed_repos
        || login.is_c_level
        || (login.is_employee && !login.is_partner)
        || !login.global_actions.is_empty()
        || login
            .projects
            .values()
            .any(|grant| !grant.actions.is_empty() || grant.can_create_repo)
}

fn parse_repository_id(bytes: &[u8]) -> Result<RepositoryId, Status> {
    let raw = <[u8; 16]>::try_from(bytes)
        .map_err(|_err| Status::invalid_argument("repository id must be exactly 16 bytes"))?;
    let ctx = Context::from(raw);
    if ctx.is_zero() {
        return Err(Status::invalid_argument(
            "repository id must not be all zeros",
        ));
    }
    Ok(RepositoryId::from(ctx))
}

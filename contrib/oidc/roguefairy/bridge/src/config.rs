// SPDX-FileCopyrightText: 2026 Rogue Fairy Studios
// SPDX-License-Identifier: MIT

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;

use serde::Deserialize;

use crate::error::ConfigError;
use crate::policy::DEFAULT_CLAIMS_KEY;
use crate::policy::GROUP_AUTHENTIK_ADMINS;
use crate::policy::GROUP_C_LEVEL;
use crate::policy::GROUP_EMPLOYEES;
use crate::policy::GROUP_PARTNERS;
use crate::policy::ProjectVisibility;
use crate::policy::is_valid_project_slug;

const DEFAULT_BIND: &str = "0.0.0.0:8190";
const DEFAULT_RESOURCE_ID_TEMPLATE: &str = "urc-{id}";
const DEFAULT_TOKEN_LIFETIME_SECONDS: u64 = 300;
const MAX_TOKEN_LIFETIME_SECONDS: u64 = 3600;

/// Group names and OIDC custom claim key evaluated by the authorization policy.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct PolicyConfig {
    #[serde(default = "default_admin_groups")]
    pub admin_groups: Vec<String>,
    #[serde(default = "default_employee_group")]
    pub employee_group: String,
    #[serde(default = "default_partner_group")]
    pub partner_group: String,
    #[serde(default = "default_claims_key")]
    pub claims_key: String,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            admin_groups: default_admin_groups(),
            employee_group: default_employee_group(),
            partner_group: default_partner_group(),
            claims_key: default_claims_key(),
        }
    }
}

fn default_admin_groups() -> Vec<String> {
    vec![GROUP_C_LEVEL.to_owned(), GROUP_AUTHENTIK_ADMINS.to_owned()]
}

fn default_employee_group() -> String {
    GROUP_EMPLOYEES.to_owned()
}

fn default_partner_group() -> String {
    GROUP_PARTNERS.to_owned()
}

fn default_claims_key() -> String {
    DEFAULT_CLAIMS_KEY.to_owned()
}

/// Identifier field on `authentik` user records mapped to Lore user IDs.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UserIdField {
    #[default]
    Username,
    Uuid,
}

impl UserIdField {
    /// Parses `"username"` or `"uuid"`, returning [`ConfigError::InvalidUserIdField`] otherwise.
    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        match raw {
            "username" => Ok(Self::Username),
            "uuid" => Ok(Self::Uuid),
            _ => Err(ConfigError::InvalidUserIdField {
                field: raw.to_owned(),
            }),
        }
    }
}

/// Static project settings declared in `bridge.toml`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct StaticProjectConfig {
    #[serde(default)]
    pub visibility: ProjectVisibility,
    /// Optional authentik group names that grant access to this project even
    /// when a token carries only a plain `groups` array without `rfs_lore`.
    #[serde(default)]
    pub read_groups: Vec<String>,
    #[serde(default)]
    pub write_groups: Vec<String>,
    #[serde(default)]
    pub lead_groups: Vec<String>,
}

/// Optional `authentik` Core API settings for user and group directory lookups.
#[derive(Clone, Default, Deserialize, PartialEq, Eq)]
pub struct AuthentikApiConfig {
    pub base_url: Option<String>,
    #[serde(skip)]
    pub api_token: Option<String>,
    #[serde(default)]
    pub user_id_field: UserIdField,
}

impl fmt::Debug for AuthentikApiConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthentikApiConfig")
            .field("base_url", &self.base_url)
            .field("api_token", &self.api_token.as_ref().map(|_| "[REDACTED]"))
            .field("user_id_field", &self.user_id_field)
            .finish()
    }
}

/// Validated runtime configuration for `rfs-lore-bridge`.
#[derive(Clone, PartialEq, Eq)]
pub struct BridgeConfig {
    pub bind: String,
    pub grpc_bind: Option<String>,
    pub issuer: String,
    pub provider_url: Option<String>,
    pub login_issuers: Vec<String>,
    pub login_audiences: Vec<String>,
    pub audience: String,
    pub root_domains: Vec<String>,
    pub resource_prefix: String,
    pub resource_id_template: String,
    pub token_lifetime_seconds: u64,
    pub state_path: Option<PathBuf>,
    pub user_state_path: Option<PathBuf>,
    pub signing_key_path: Option<PathBuf>,
    pub signing_key_b64: Option<String>,
    pub authentik: AuthentikApiConfig,
    pub policy: PolicyConfig,
    pub projects: BTreeMap<String, StaticProjectConfig>,
}

impl fmt::Debug for BridgeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BridgeConfig")
            .field("bind", &self.bind)
            .field("grpc_bind", &self.grpc_bind)
            .field("issuer", &self.issuer)
            .field("provider_url", &self.provider_url)
            .field("login_issuers", &self.login_issuers)
            .field("login_audiences", &self.login_audiences)
            .field("audience", &self.audience)
            .field("root_domains", &self.root_domains)
            .field("resource_prefix", &self.resource_prefix)
            .field("resource_id_template", &self.resource_id_template)
            .field("token_lifetime_seconds", &self.token_lifetime_seconds)
            .field("state_path", &self.state_path)
            .field("user_state_path", &self.user_state_path)
            .field("signing_key_path", &self.signing_key_path)
            .field(
                "signing_key_b64",
                &self.signing_key_b64.as_ref().map(|_| "[REDACTED]"),
            )
            .field("authentik", &self.authentik)
            .field("policy", &self.policy)
            .field("projects", &self.projects)
            .finish()
    }
}

fn default_bind() -> String {
    DEFAULT_BIND.to_owned()
}

fn default_resource_id_template() -> String {
    DEFAULT_RESOURCE_ID_TEMPLATE.to_owned()
}

const RESERVED_CLAIMS_KEYS: [&str; 30] = [
    "iss",
    "sub",
    "aud",
    "exp",
    "nbf",
    "iat",
    "jti",
    "azp",
    "scope",
    "client_id",
    "nonce",
    "auth_time",
    "at_hash",
    "c_hash",
    "acr",
    "amr",
    "sid",
    "typ",
    "cnf",
    "act",
    "may_act",
    "identity",
    "https://lore.org/claims/identity",
    "https://lore.org/claims/root_domains",
    "preferred_username",
    "name",
    "is_service_account",
    "groups",
    "root_domains",
    "resources",
];

#[derive(Default, Deserialize)]
struct PartialAuthentikApiConfig {
    base_url: Option<String>,
    user_id_field: Option<String>,
}

#[derive(Default, Deserialize)]
struct PartialPolicyConfig {
    admin_groups: Option<Vec<String>>,
    employee_group: Option<String>,
    partner_group: Option<String>,
    claims_key: Option<String>,
}

/// Raw configuration where every field is optional before environment overrides run.
#[derive(Default, Deserialize)]
struct PartialBridgeConfig {
    bind: Option<String>,
    grpc_bind: Option<String>,
    issuer: Option<String>,
    provider_url: Option<String>,
    login_issuers: Option<Vec<String>>,
    login_audiences: Option<Vec<String>>,
    audience: Option<String>,
    root_domains: Option<Vec<String>>,
    resource_prefix: Option<String>,
    resource_id_template: Option<String>,
    token_lifetime_seconds: Option<u64>,
    state_path: Option<String>,
    user_state_path: Option<String>,
    signing_key_path: Option<String>,
    #[serde(default)]
    authentik: PartialAuthentikApiConfig,
    #[serde(default)]
    policy: PartialPolicyConfig,
    #[serde(default)]
    projects: BTreeMap<String, StaticProjectConfig>,
}

impl BridgeConfig {
    /// Loads configuration from an optional TOML path and environment overrides.
    pub fn load(
        path: Option<&Path>,
        env_lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, ConfigError> {
        let partial = match path {
            Some(file_path) => {
                let raw =
                    std::fs::read_to_string(file_path).map_err(|source| ConfigError::ReadFile {
                        path: file_path.to_path_buf(),
                        source,
                    })?;
                toml::from_str::<PartialBridgeConfig>(&raw)?
            }
            None => PartialBridgeConfig::default(),
        };

        Self::from_partial_and_env(partial, env_lookup)
    }

    /// Parses configuration directly from a TOML string without reading environment variables.
    pub fn from_toml_str(raw: &str) -> Result<Self, ConfigError> {
        let partial: PartialBridgeConfig = toml::from_str(raw)?;
        Self::from_partial_and_env(partial, |_| None)
    }

    fn from_partial_and_env(
        partial: PartialBridgeConfig,
        env_lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, ConfigError> {
        let non_empty = |key: &str| {
            env_lookup(key).and_then(|val| {
                let trimmed = val.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_owned())
            })
        };

        let bind = non_empty("RFS_LORE_BIND")
            .or_else(|| trim_non_empty(partial.bind))
            .or_else(|| non_empty("PORT").map(|port| format!("0.0.0.0:{port}")))
            .unwrap_or_else(default_bind);

        let grpc_bind =
            non_empty("RFS_LORE_GRPC_BIND").or_else(|| trim_non_empty(partial.grpc_bind));
        let issuer = non_empty("RFS_LORE_ISSUER")
            .or_else(|| partial.issuer.map(|s| s.trim().to_owned()))
            .unwrap_or_default()
            .trim_end_matches('/')
            .to_owned();
        let provider_url =
            non_empty("RFS_LORE_PROVIDER_URL").or_else(|| trim_non_empty(partial.provider_url));
        let login_issuers = non_empty("RFS_LORE_LOGIN_ISSUERS")
            .map(|val| split_csv(&val))
            .or_else(|| partial.login_issuers.map(trim_vec_preserve_empty))
            .unwrap_or_default();
        let audience = non_empty("RFS_LORE_AUDIENCE")
            .or_else(|| partial.audience.map(|s| s.trim().to_owned()))
            .unwrap_or_default();
        let login_audiences = non_empty("RFS_LORE_LOGIN_AUDIENCES")
            .map(|val| split_csv(&val))
            .or_else(|| partial.login_audiences.map(trim_vec_preserve_empty))
            .unwrap_or_else(|| {
                if audience.is_empty() {
                    Vec::new()
                } else {
                    vec![audience.clone()]
                }
            });
        let root_domains = match non_empty("RFS_LORE_ROOT_DOMAINS") {
            Some(val) => normalize_root_domains(split_csv(&val)),
            None => match partial.root_domains {
                Some(items) => normalize_root_domains(items),
                None => default_root_domains_from_endpoints(&issuer, &audience),
            },
        };
        let resource_prefix = non_empty("RFS_LORE_RESOURCE_PREFIX")
            .or_else(|| partial.resource_prefix.map(|s| s.trim().to_owned()))
            .unwrap_or_default();
        let resource_id_template = non_empty("RFS_LORE_RESOURCE_ID_TEMPLATE")
            .or_else(|| partial.resource_id_template.map(|s| s.trim().to_owned()))
            .unwrap_or_else(default_resource_id_template);
        let token_lifetime_seconds = match non_empty("RFS_LORE_TOKEN_LIFETIME_SECONDS") {
            Some(raw) => raw.trim().parse::<u64>().map_err(|source| {
                ConfigError::InvalidTokenLifetimeEnv {
                    raw: raw.clone(),
                    source,
                }
            })?,
            None => partial
                .token_lifetime_seconds
                .unwrap_or(DEFAULT_TOKEN_LIFETIME_SECONDS),
        };
        let state_path = non_empty("RFS_LORE_STATE_PATH")
            .or_else(|| trim_non_empty(partial.state_path))
            .map(PathBuf::from);
        let user_state_path = non_empty("RFS_LORE_USER_STATE_PATH")
            .or_else(|| trim_non_empty(partial.user_state_path))
            .map(PathBuf::from);
        let signing_key_path = non_empty("RFS_LORE_SIGNING_KEY_PATH")
            .or_else(|| trim_non_empty(partial.signing_key_path))
            .map(PathBuf::from);
        let signing_key_b64 = non_empty("RFS_LORE_SIGNING_KEY_B64");

        let user_id_field = match non_empty("RFS_LORE_AUTHENTIK_USER_ID_FIELD")
            .or_else(|| trim_non_empty(partial.authentik.user_id_field))
        {
            Some(raw) => UserIdField::parse(&raw)?,
            None => UserIdField::Username,
        };
        let authentik = AuthentikApiConfig {
            base_url: non_empty("RFS_LORE_AUTHENTIK_URL")
                .or_else(|| trim_non_empty(partial.authentik.base_url)),
            api_token: non_empty("RFS_LORE_AUTHENTIK_API_TOKEN"),
            user_id_field,
        };

        let default_policy = PolicyConfig::default();
        let policy = PolicyConfig {
            admin_groups: env_lookup("RFS_LORE_POLICY_ADMIN_GROUPS")
                .map(|val| split_csv(&val))
                .or_else(|| partial.policy.admin_groups.map(trim_vec_preserve_empty))
                .unwrap_or(default_policy.admin_groups),
            employee_group: env_lookup("RFS_LORE_POLICY_EMPLOYEE_GROUP")
                .map(|val| val.trim().to_owned())
                .or_else(|| partial.policy.employee_group.map(|s| s.trim().to_owned()))
                .unwrap_or(default_policy.employee_group),
            partner_group: env_lookup("RFS_LORE_POLICY_PARTNER_GROUP")
                .map(|val| val.trim().to_owned())
                .or_else(|| partial.policy.partner_group.map(|s| s.trim().to_owned()))
                .unwrap_or(default_policy.partner_group),
            claims_key: non_empty("RFS_LORE_POLICY_CLAIMS_KEY")
                .or_else(|| partial.policy.claims_key.map(|s| s.trim().to_owned()))
                .unwrap_or(default_policy.claims_key),
        };

        let projects = partial
            .projects
            .into_iter()
            .map(|(slug, proj)| {
                (
                    slug,
                    StaticProjectConfig {
                        visibility: proj.visibility,
                        read_groups: trim_vec_preserve_empty(proj.read_groups),
                        write_groups: trim_vec_preserve_empty(proj.write_groups),
                        lead_groups: trim_vec_preserve_empty(proj.lead_groups),
                    },
                )
            })
            .collect();

        let config = Self {
            bind,
            grpc_bind,
            issuer,
            provider_url,
            login_issuers,
            login_audiences,
            audience,
            root_domains,
            resource_prefix,
            resource_id_template,
            token_lifetime_seconds,
            state_path,
            user_state_path,
            signing_key_path,
            signing_key_b64,
            authentik,
            policy,
            projects,
        };
        config.validate()?;
        Ok(config)
    }

    /// Parses and returns the primary HTTP/gRPC socket address.
    pub fn bind_addr(&self) -> Result<SocketAddr, ConfigError> {
        self.bind
            .parse::<SocketAddr>()
            .map_err(|source| ConfigError::InvalidBindAddress {
                address: self.bind.clone(),
                source,
            })
    }

    /// Parses and returns the optional dedicated gRPC socket address.
    pub fn grpc_bind_addr(&self) -> Result<Option<SocketAddr>, ConfigError> {
        self.grpc_bind
            .as_ref()
            .map(|addr| {
                addr.parse::<SocketAddr>()
                    .map_err(|source| ConfigError::InvalidBindAddress {
                        address: addr.clone(),
                        source,
                    })
            })
            .transpose()
    }

    /// Validates all configuration invariants.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let bind_addr = self.bind_addr()?;
        if let Some(grpc_addr) = self.grpc_bind_addr()?
            && bind_addrs_conflict(bind_addr, grpc_addr)
        {
            return Err(ConfigError::DuplicateBindAddress { address: grpc_addr });
        }

        let issuer_url = parse_clean_http_url(&self.issuer, false).map_err(|_reason| {
            ConfigError::InvalidUrl {
                field: "issuer",
                value: self.issuer.clone(),
            }
        })?;
        if let Some(provider_url) = &self.provider_url {
            validate_http_url("provider_url", provider_url)?;
        }
        if self.login_issuers.is_empty()
            || self.login_issuers.iter().any(|iss| iss.trim().is_empty())
        {
            return Err(ConfigError::EmptyField {
                field: "login_issuers",
            });
        }
        let normalized_issuer = self.issuer.trim_end_matches('/');
        for login_issuer in &self.login_issuers {
            validate_http_url("login_issuers", login_issuer)?;
            if login_issuer.trim_end_matches('/') == normalized_issuer {
                return Err(ConfigError::SelfLoginIssuer {
                    issuer: login_issuer.clone(),
                });
            }
        }
        if self.audience.trim().is_empty() {
            return Err(ConfigError::EmptyField { field: "audience" });
        }
        if self.login_audiences.is_empty()
            || self.login_audiences.iter().any(|aud| aud.trim().is_empty())
        {
            return Err(ConfigError::EmptyField {
                field: "login_audiences",
            });
        }
        if self.root_domains.is_empty()
            || self.root_domains.iter().any(|dom| {
                let trimmed = dom.trim();
                trimmed.strip_prefix('.').unwrap_or(trimmed).is_empty()
            })
        {
            return Err(ConfigError::EmptyField {
                field: "root_domains",
            });
        }
        if let Some(issuer_host) = issuer_url.host_str()
            && !domain_in_root_domains(issuer_host, &self.root_domains)
        {
            return Err(ConfigError::UncoveredRootDomain {
                field: "issuer",
                host: issuer_host.to_owned(),
            });
        }
        if let Ok(audience_url) = parse_clean_http_url(&self.audience, false)
            && let Some(audience_host) = audience_url.host_str()
            && !domain_in_root_domains(audience_host, &self.root_domains)
        {
            return Err(ConfigError::UncoveredRootDomain {
                field: "audience",
                host: audience_host.to_owned(),
            });
        }
        if self.resource_prefix.trim().is_empty() {
            return Err(ConfigError::EmptyField {
                field: "resource_prefix",
            });
        }
        if !self.resource_id_template.contains("{id}") {
            return Err(ConfigError::MissingIdPlaceholder {
                template: self.resource_id_template.clone(),
            });
        }
        if self.token_lifetime_seconds == 0
            || self.token_lifetime_seconds > MAX_TOKEN_LIFETIME_SECONDS
        {
            return Err(ConfigError::InvalidTokenLifetime {
                seconds: self.token_lifetime_seconds,
            });
        }
        let claims_key_trimmed = self.policy.claims_key.trim();
        if claims_key_trimmed.is_empty() {
            return Err(ConfigError::EmptyField {
                field: "policy.claims_key",
            });
        }
        if RESERVED_CLAIMS_KEYS.contains(&claims_key_trimmed) {
            return Err(ConfigError::ReservedClaimsKey {
                key: self.policy.claims_key.clone(),
            });
        }
        if self.policy.admin_groups.iter().any(|g| g.trim().is_empty()) {
            return Err(ConfigError::EmptyField {
                field: "policy.admin_groups",
            });
        }
        let partner_trimmed = self.policy.partner_group.trim();
        if !partner_trimmed.is_empty()
            && (partner_trimmed == self.policy.employee_group.trim()
                || self
                    .policy
                    .admin_groups
                    .iter()
                    .any(|adm| adm.trim() == partner_trimmed))
        {
            return Err(ConfigError::OverlappingPolicyGroups {
                group: self.policy.partner_group.clone(),
            });
        }
        if let Some(base_url) = &self.authentik.base_url {
            validate_http_url("authentik.base_url", base_url)?;
        }
        if let Some(token) = &self.authentik.api_token
            && (token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()))
        {
            return Err(ConfigError::InvalidApiToken);
        }
        for (slug, proj) in &self.projects {
            if !is_valid_project_slug(slug) {
                return Err(ConfigError::InvalidProjectSlug { slug: slug.clone() });
            }
            if proj.read_groups.iter().any(|g| g.trim().is_empty()) {
                return Err(ConfigError::EmptyField {
                    field: "projects.read_groups",
                });
            }
            if proj.write_groups.iter().any(|g| g.trim().is_empty()) {
                return Err(ConfigError::EmptyField {
                    field: "projects.write_groups",
                });
            }
            if proj.lead_groups.iter().any(|g| g.trim().is_empty()) {
                return Err(ConfigError::EmptyField {
                    field: "projects.lead_groups",
                });
            }
        }
        Ok(())
    }
}

fn normalize_root_domains(items: Vec<String>) -> Vec<String> {
    items
        .into_iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .collect()
}

fn default_root_domains_from_endpoints(issuer: &str, audience: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in [issuer, audience] {
        if let Ok(parsed) = parse_clean_http_url(raw, false)
            && let Some(host) = parsed.host_str()
        {
            let lower = host.to_ascii_lowercase();
            if !out.contains(&lower) {
                out.push(lower);
            }
        }
    }
    out
}

/// Mirrors `lore_credential::util::domain_in_root_domains` on label boundaries without heap allocation.
fn domain_in_root_domains(host: &str, root_domains: &[String]) -> bool {
    let host_bytes = host.as_bytes();
    root_domains.iter().any(|raw| {
        let trimmed = raw.trim();
        let apex_bytes = trimmed.strip_prefix('.').unwrap_or(trimmed).as_bytes();
        !apex_bytes.is_empty()
            && (host_bytes.eq_ignore_ascii_case(apex_bytes)
                || (host_bytes.len() > apex_bytes.len()
                    && host_bytes[host_bytes.len() - apex_bytes.len() - 1] == b'.'
                    && host_bytes[host_bytes.len() - apex_bytes.len()..]
                        .eq_ignore_ascii_case(apex_bytes)))
    })
}

fn trim_non_empty(raw: Option<String>) -> Option<String> {
    raw.and_then(|val| {
        let trimmed = val.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}

fn trim_vec_preserve_empty(items: Vec<String>) -> Vec<String> {
    items.into_iter().map(|s| s.trim().to_owned()).collect()
}

fn bind_addrs_conflict(primary: SocketAddr, secondary: SocketAddr) -> bool {
    primary.port() != 0
        && primary.port() == secondary.port()
        && (primary.ip().to_canonical() == secondary.ip().to_canonical()
            || primary.ip().is_unspecified()
            || secondary.ip().is_unspecified())
}

fn split_csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect()
}

fn validate_http_url(field: &'static str, value: &str) -> Result<(), ConfigError> {
    parse_clean_http_url(value, false).map_err(|_reason| ConfigError::InvalidUrl {
        field,
        value: value.to_owned(),
    })?;
    Ok(())
}

/// Parses `raw` as an `http` or `https` URL without credentials or fragments, and optionally without a query string.
pub(crate) fn parse_clean_http_url(raw: &str, allow_query: bool) -> Result<url::Url, String> {
    let parsed = url::Url::parse(raw).map_err(|err| format!("invalid URL '{raw}': {err}"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || (!allow_query && parsed.query().is_some())
    {
        return Err(format!("disallowed URL components in '{raw}'"));
    }
    Ok(parsed)
}

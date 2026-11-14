// SPDX-FileCopyrightText: 2026 Rogue Fairy Studios
// SPDX-License-Identifier: MIT

use std::path::PathBuf;

use thiserror::Error;

/// Configuration loading and validation errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read configuration file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse configuration TOML: {0}")]
    ParseToml(#[from] toml::de::Error),
    #[error("invalid bind address '{address}': {source}")]
    InvalidBindAddress {
        address: String,
        source: std::net::AddrParseError,
    },
    #[error("bind and grpc_bind conflict on socket address '{address}'")]
    DuplicateBindAddress { address: std::net::SocketAddr },
    #[error(
        "authentik.api_token must be non-empty printable ASCII without whitespace or control characters"
    )]
    InvalidApiToken,
    #[error("invalid URL for '{field}' ('{value}')")]
    InvalidUrl { field: &'static str, value: String },
    #[error("'{field}' must not be empty")]
    EmptyField { field: &'static str },
    #[error("resource_id_template '{template}' must contain '{{id}}'")]
    MissingIdPlaceholder { template: String },
    #[error("token_lifetime_seconds ({seconds}) must be between 1 and 3600")]
    InvalidTokenLifetime { seconds: u64 },
    #[error("invalid RFS_LORE_TOKEN_LIFETIME_SECONDS '{raw}': {source}")]
    InvalidTokenLifetimeEnv {
        raw: String,
        #[source]
        source: std::num::ParseIntError,
    },
    #[error("invalid static project slug '{slug}' in [projects]")]
    InvalidProjectSlug { slug: String },
    #[error("invalid authentik.user_id_field '{field}': expected 'username' or 'uuid'")]
    InvalidUserIdField { field: String },
    #[error("login_issuers must not include the bridge's own issuer '{issuer}'")]
    SelfLoginIssuer { issuer: String },
    #[error("'{field}' host '{host}' is not covered by root_domains")]
    UncoveredRootDomain { field: &'static str, host: String },
    #[error("policy group '{group}' overlaps across mutually exclusive studio role tiers")]
    OverlappingPolicyGroups { group: String },
    #[error("policy.claims_key '{key}' collides with a reserved JWT claim name")]
    ReservedClaimsKey { key: String },
}

/// Signing key loading, generation, and JWT minting errors.
#[derive(Debug, Error)]
pub enum SigningError {
    #[error("failed to generate P-256 signing key")]
    KeyGeneration,
    #[error("failed to decode base64 signing key: {0}")]
    InvalidBase64(#[from] base64::DecodeError),
    #[error("invalid PKCS#8 P-256 signing key")]
    InvalidPkcs8Key,
    #[error("failed to read signing key at {path}: {source}")]
    ReadKeyFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to write signing key at {path}: {source}")]
    WriteKeyFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("unexpected uncompressed EC public key format")]
    InvalidPublicKeyPoint,
    #[error("failed to serialize JWT claims: {0}")]
    SerializeClaims(#[from] serde_json::Error),
    #[error("failed to sign JWT payload")]
    SignFailed,
    #[error("failed to construct JWT decoding key: {0}")]
    BuildDecodingKey(#[from] jsonwebtoken::errors::Error),
}

/// Bearer and subject token verification errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthVerifyError {
    #[error("missing bearer authorization header")]
    MissingBearerToken,
    #[error("malformed authorization header")]
    MalformedAuthorizationHeader,
    #[error("bearer token exceeds maximum permitted size")]
    TokenTooLarge,
    #[error("malformed JWT header or payload")]
    MalformedToken,
    #[error("JWT header carries no key id")]
    MissingKeyId,
    #[error("token issuer '{issuer}' is not accepted")]
    IssuerNotAccepted { issuer: String },
    #[error("signing key '{kid}' not found for issuer '{issuer}'")]
    UnknownSigningKey { issuer: String, kid: String },
    #[error("token validation failed")]
    InvalidToken,
    #[error("token carries no usable caller identity")]
    MissingIdentity,
    #[error("identity provider JWKS is unavailable for '{issuer}'")]
    ProviderUnavailable { issuer: String },
}

/// Repository naming and authorization policy errors.
///
/// Every naming variant carries the `"Missing resource context in resourceName"` marker
/// required by Lore Server's `RepositoryRegistry` to surface client naming errors as
/// `INVALID_ARGUMENT` rather than `INTERNAL`.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error(
        "Missing resource context in resourceName: repository name is empty or exceeds 1000 bytes"
    )]
    InvalidRepositoryNameLength,
    #[error("Missing resource context in resourceName: expected <project>/<repository>")]
    MissingProjectNamespace,
    #[error("Missing resource context in resourceName: invalid project slug '{project}'")]
    InvalidProjectSlug { project: String },
    #[error(
        "Missing resource context in resourceName: invalid repository path segment in '{name}'"
    )]
    InvalidRepositorySegment { name: String },
}

/// Repository registry and user directory storage errors.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("failed to read state file {path}: {source}")]
    ReadState {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("state file {path} ({size} bytes) exceeds {max_bytes} byte limit")]
    StateFileTooLarge {
        path: PathBuf,
        size: u64,
        max_bytes: u64,
    },
    #[error("unsupported state schema version {version}")]
    UnsupportedStateVersion { version: u32 },
    #[error("invalid persisted repository '{id}': {reason}")]
    InvalidPersistedRepository { id: String, reason: String },
    #[error("failed to write state file {path}: {source}")]
    WriteState {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse state JSON: {0}")]
    ParseState(#[from] serde_json::Error),
    #[error("blocking persistence task failed: {0}")]
    PersistenceTaskFailed(#[source] tokio::task::JoinError),
    #[error("repository '{id}' is already registered under name '{existing_name}'")]
    RepositoryIdConflict { id: String, existing_name: String },
    #[error("repository name '{name}' is already registered under another id")]
    RepositoryNameConflict { name: String },
    #[error("registry capacity reached ({limit} entries)")]
    CapacityExceeded { limit: usize },
}

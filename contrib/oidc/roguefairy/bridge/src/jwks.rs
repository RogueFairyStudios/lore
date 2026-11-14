// SPDX-FileCopyrightText: 2026 Rogue Fairy Studios
// SPDX-License-Identifier: MIT

use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::AlgorithmParameters;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::jwk::KeyAlgorithm;
use jsonwebtoken::jwk::KeyOperations;
use jsonwebtoken::jwk::PublicKeyUse;
use parking_lot::Mutex;
use parking_lot::RwLock;
use serde::Deserialize;
use tracing::debug;
use tracing::warn;

use crate::config::BridgeConfig;
use crate::config::UserIdField;
use crate::error::AuthVerifyError;
use crate::policy::CallerClaims;
use crate::policy::PresentStringClaim;
use crate::policy::ProjectVisibility;
use crate::policy::VerifiedCaller;
use crate::policy::VerifiedExchangedCaller;
use crate::signing::TokenSigner;
use crate::store::UserRecord;

pub const MAX_BEARER_TOKEN_BYTES: usize = 16 * 1024;
pub(crate) const MAX_USER_ID_BYTES: usize = 256;
pub(crate) const MAX_USERNAME_BYTES: usize = 256;
pub(crate) const MAX_DISPLAY_NAME_BYTES: usize = 512;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
#[lore_macro::test_pub]
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(10);
const INITIAL_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const MAX_HTTP_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_KEYS_PER_ISSUER: usize = 64;
const NEGATIVE_USER_CACHE_TTL: Duration = Duration::from_secs(60);
const CONFLICT_RESOLUTION_COOLDOWN: Duration = Duration::from_secs(10);
pub(crate) const JWT_CLOCK_SKEW_LEEWAY_SECS: u64 = 60;
#[lore_macro::test_pub]
const MAX_NEGATIVE_USER_CACHE_ENTRIES: usize = 4096;
const GROUP_CACHE_TTL: Duration = Duration::from_secs(60);
const DISCOVERY_URL_TTL: Duration = Duration::from_secs(300);
const MAX_GROUP_PAGES: usize = 50;
#[lore_macro::test_pub]
const MAX_DISPLAY_NAME_PAGES: usize = 5;

#[derive(Clone, Copy)]
enum NegativeLookup {
    Id,
    Username,
    DisplayName,
}

#[derive(Default)]
struct NegativeBucket {
    entries: HashMap<Arc<str>, (Instant, u64)>,
    order: VecDeque<(Arc<str>, u64)>,
}

impl NegativeBucket {
    fn contains_fresh(&mut self, key: &str, now: Instant, ttl: Duration) -> bool {
        if let Some(&(recorded_at, _)) = self.entries.get(key) {
            if now.saturating_duration_since(recorded_at) < ttl {
                return true;
            }
            self.entries.remove(key);
        }
        false
    }

    fn record(&mut self, key: &str, now: Instant, seq: u64) {
        if let Some(shared) = self.entries.get_key_value(key).map(|(k, _)| Arc::clone(k)) {
            if let Some(slot) = self.entries.get_mut(shared.as_ref()) {
                *slot = (now, seq);
            }
            self.order.push_back((shared, seq));
            if self.order.len() > 2 * MAX_NEGATIVE_USER_CACHE_ENTRIES {
                self.compact_stale_queue();
            }
            return;
        }

        while self.entries.len() >= MAX_NEGATIVE_USER_CACHE_ENTRIES {
            let Some((oldest_key, queued_seq)) = self.order.pop_front() else {
                break;
            };
            if let Some(&(_, current_seq)) = self.entries.get(oldest_key.as_ref())
                && current_seq == queued_seq
            {
                self.entries.remove(oldest_key.as_ref());
            }
        }

        let shared: Arc<str> = Arc::from(key);
        self.entries.insert(Arc::clone(&shared), (now, seq));
        self.order.push_back((shared, seq));
        if self.order.len() > 2 * MAX_NEGATIVE_USER_CACHE_ENTRIES {
            self.compact_stale_queue();
        }
    }

    fn compact_stale_queue(&mut self) {
        let entries = &self.entries;
        self.order.retain(|(k, seq)| {
            entries
                .get(k.as_ref())
                .is_some_and(|&(_, current_seq)| current_seq == *seq)
        });
    }

    fn remove(&mut self, key: &str) {
        self.entries.remove(key);
    }
}

#[derive(Default)]
struct NegativeUserCache {
    clock: u64,
    by_id: NegativeBucket,
    by_username: NegativeBucket,
    by_display_name: NegativeBucket,
    conflict_cooldown: NegativeBucket,
}

#[derive(Default)]
struct GroupCacheState {
    projects: Arc<HashMap<String, ProjectVisibility>>,
    last_attempt: Option<Instant>,
    last_success: Option<Instant>,
    last_refresh_failed: bool,
    #[cfg(feature = "test-util")]
    force_expired: bool,
}

#[derive(Default)]
struct GroupVisibilityCache {
    state: RwLock<GroupCacheState>,
    refresh_gate: tokio::sync::Mutex<()>,
}

/// Transient failure querying the `authentik` Core user directory API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthentikDirectoryError {
    Unavailable,
}

/// Result of resolving a project's visibility from `authentik` `/api/v3/core/groups/`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthentikProjectLookup {
    NotConfigured,
    Unavailable,
    NotFound,
    Found(ProjectVisibility),
}

enum LoginDecodeFailure {
    SignatureOrAlgorithm,
    MalformedToken,
    InvalidClaims,
    MissingIdentity,
}

struct CachedKey {
    jwk: Jwk,
    decoding_key: DecodingKey,
    algorithm: Algorithm,
}

#[derive(Default)]
struct IssuerCacheState {
    keys: HashMap<String, Arc<CachedKey>>,
    jwks_url: Option<url::Url>,
    jwks_url_discovered_at: Option<Instant>,
    last_attempt: Option<Instant>,
    last_success: Option<Instant>,
    last_refresh_failed: bool,
}

struct IssuerKeyCache {
    issuer: String,
    configured_issuer: Option<url::Url>,
    discovery_url: Option<url::Url>,
    login_audiences: Vec<String>,
    provider_url: Option<url::Url>,
    state: RwLock<IssuerCacheState>,
    refresh_gate: tokio::sync::Mutex<()>,
    client: reqwest::Client,
}

enum JwksFetchError {
    EndpointMissing,
    Other(String),
}

impl JwksFetchError {
    fn into_reason(self) -> String {
        match self {
            Self::EndpointMissing => "JWKS endpoint returned HTTP 404 or 410".to_owned(),
            Self::Other(reason) => reason,
        }
    }
}

#[derive(Deserialize)]
struct OidcDiscoveryDocument {
    issuer: String,
    jwks_uri: String,
}

#[derive(Deserialize)]
struct UnverifiedIssuerProbe<'a> {
    #[serde(borrow)]
    iss: Cow<'a, str>,
}

fn deserialize_present_any<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let _: serde::de::IgnoredAny = serde::Deserialize::deserialize(deserializer)?;
    Ok(true)
}

#[derive(Deserialize)]
struct CompactJwtHeader<'a> {
    alg: Algorithm,
    #[serde(default, borrow)]
    typ: Option<Cow<'a, str>>,
    #[serde(default, borrow)]
    kid: Option<Cow<'a, str>>,
    #[serde(default, deserialize_with = "deserialize_present_any")]
    crit: bool,
}

#[lore_macro::test_pub]
type StackJwtPayloadBuf = [u8; 4096];

#[lore_macro::test_pub]
struct SplitJwt<'a> {
    signing_input: &'a [u8],
    header_b64: &'a str,
    payload_b64: &'a str,
    signature_b64: &'a str,
}

enum FastVerifyOutcome {
    Exchanged(VerifiedExchangedCaller),
    Login(CallerClaims),
    NeedsAsyncLogin {
        alg: Algorithm,
        kid: String,
        issuer: String,
        used_cached_jwk: Option<Jwk>,
    },
}

/// Verifies `authentik` login tokens and Bridge-minted `at+jwt` tokens, with
/// optional `authentik` Core API user and project-group lookups.
pub struct TokenVerifier {
    config: BridgeConfig,
    signer: TokenSigner,
    authentik_base_url: Option<url::Url>,
    login_caches: HashMap<String, Arc<IssuerKeyCache>>,
    group_cache: GroupVisibilityCache,
    negative_user_cache: Mutex<NegativeUserCache>,
    http_client: reqwest::Client,
}

impl TokenVerifier {
    /// Builds a `TokenVerifier` for the configured `login_issuers` and local `signer`.
    pub fn new(config: BridgeConfig, signer: TokenSigner) -> Result<Self, reqwest::Error> {
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()?;

        let provider_url = config
            .provider_url
            .as_deref()
            .and_then(|raw| crate::config::parse_clean_http_url(raw, false).ok());

        let mut login_issuer_origins = Vec::with_capacity(config.login_issuers.len());
        let mut login_caches = HashMap::with_capacity(config.login_issuers.len());
        for issuer in &config.login_issuers {
            let configured_issuer = crate::config::parse_clean_http_url(issuer, false).ok();
            if let Some(ref parsed_issuer) = configured_issuer {
                login_issuer_origins.push(parsed_issuer.origin());
            }
            let discovery_raw = format!(
                "{}/.well-known/openid-configuration",
                issuer.trim_end_matches('/')
            );
            let discovery_url = crate::config::parse_clean_http_url(&discovery_raw, false)
                .ok()
                .and_then(|parsed| match &provider_url {
                    Some(provider) => rewrite_origin_url(parsed, provider),
                    None => Some(parsed),
                });
            login_caches.insert(
                issuer.clone(),
                Arc::new(IssuerKeyCache {
                    issuer: issuer.clone(),
                    configured_issuer,
                    discovery_url,
                    login_audiences: config.login_audiences.clone(),
                    provider_url: provider_url.clone(),
                    state: RwLock::new(IssuerCacheState::default()),
                    refresh_gate: tokio::sync::Mutex::new(()),
                    client: http_client.clone(),
                }),
            );
        }

        let authentik_base_url = config
            .authentik
            .base_url
            .as_deref()
            .and_then(|raw| crate::config::parse_clean_http_url(raw, false).ok())
            .and_then(|parsed| match &provider_url {
                Some(provider)
                    if login_issuer_origins
                        .iter()
                        .any(|issuer_origin| *issuer_origin == parsed.origin()) =>
                {
                    rewrite_origin_url(parsed, provider)
                }
                _ => Some(parsed),
            });

        Ok(Self {
            config,
            signer,
            authentik_base_url,
            login_caches,
            group_cache: GroupVisibilityCache::default(),
            negative_user_cache: Mutex::new(NegativeUserCache::default()),
            http_client,
        })
    }

    /// Returns whether outbound `authentik` Core API queries are configured.
    pub fn has_authentik_api(&self) -> bool {
        self.authentik_base_url.is_some() && self.config.authentik.api_token.is_some()
    }

    /// Extracts a bearer token from an HTTP/gRPC `authorization` header value.
    pub fn extract_bearer(header_value: Option<&str>) -> Result<&str, AuthVerifyError> {
        let raw = header_value.ok_or(AuthVerifyError::MissingBearerToken)?;
        let (scheme, token) = raw
            .split_once(' ')
            .ok_or(AuthVerifyError::MalformedAuthorizationHeader)?;
        if !scheme.eq_ignore_ascii_case("bearer") {
            return Err(AuthVerifyError::MalformedAuthorizationHeader);
        }
        let token = token.trim();
        if token.is_empty() {
            return Err(AuthVerifyError::MalformedAuthorizationHeader);
        }
        if token.len() > MAX_BEARER_TOKEN_BYTES {
            return Err(AuthVerifyError::TokenTooLarge);
        }
        Ok(token)
    }

    /// Verifies an `authentik` login token (`subject_token` on `/token`, `RepositoryList`, `RepositoryRegister`).
    ///
    /// Refuses tokens signed by the Bridge's own exchange key so an exchanged
    /// `at+jwt` cannot be re-exchanged or used as a broad login credential.
    pub async fn verify_login_token(&self, token: &str) -> Result<CallerClaims, AuthVerifyError> {
        if token.len() > MAX_BEARER_TOKEN_BYTES {
            return Err(AuthVerifyError::TokenTooLarge);
        }
        let parts = split_jwt(token)?;
        match self.try_verify_token_fast(&parts, false)? {
            FastVerifyOutcome::Login(caller) => Ok(caller),
            FastVerifyOutcome::Exchanged(_) => Err(AuthVerifyError::InvalidToken),
            FastVerifyOutcome::NeedsAsyncLogin {
                alg,
                kid,
                issuer,
                used_cached_jwk,
            } => {
                Box::pin(self.verify_login_token_slow(&parts, alg, kid, issuer, used_cached_jwk))
                    .await
            }
        }
    }

    /// Verifies either a Bridge-signed `at+jwt` token or an `authentik` login token.
    pub async fn verify_any_token(&self, token: &str) -> Result<VerifiedCaller, AuthVerifyError> {
        if token.len() > MAX_BEARER_TOKEN_BYTES {
            return Err(AuthVerifyError::TokenTooLarge);
        }
        let parts = split_jwt(token)?;
        match self.try_verify_token_fast(&parts, true)? {
            FastVerifyOutcome::Exchanged(exchanged) => Ok(VerifiedCaller::Exchanged(exchanged)),
            FastVerifyOutcome::Login(login) => Ok(VerifiedCaller::Login(Box::new(login))),
            FastVerifyOutcome::NeedsAsyncLogin {
                alg,
                kid,
                issuer,
                used_cached_jwk,
            } => {
                let login = Box::pin(self.verify_login_token_slow(
                    &parts,
                    alg,
                    kid,
                    issuer,
                    used_cached_jwk,
                ))
                .await?;
                Ok(VerifiedCaller::Login(Box::new(login)))
            }
        }
    }

    fn try_verify_token_fast(
        &self,
        parts: &SplitJwt<'_>,
        allow_exchanged: bool,
    ) -> Result<FastVerifyOutcome, AuthVerifyError> {
        let mut header_buf = [0_u8; 1024];
        let mut header_heap = Vec::new();
        let header_bytes = decode_jwt_segment(parts.header_b64, &mut header_buf, &mut header_heap)?;
        let header: CompactJwtHeader<'_> =
            serde_json::from_slice(header_bytes).map_err(|_err| AuthVerifyError::MalformedToken)?;
        if header.crit {
            return Err(AuthVerifyError::InvalidToken);
        }

        if header.typ.as_deref().is_some_and(is_at_jwt_typ) {
            if !allow_exchanged {
                return Err(AuthVerifyError::InvalidToken);
            }
            let exchanged =
                self.verify_exchanged_parts(parts, header.alg, header.kid.as_deref())?;
            return Ok(FastVerifyOutcome::Exchanged(exchanged));
        }
        if !header.typ.as_deref().is_none_or(is_login_jwt_typ) {
            return Err(AuthVerifyError::InvalidToken);
        }
        let kid = header.kid.as_deref().ok_or(AuthVerifyError::MissingKeyId)?;
        if kid == self.signer.kid() {
            return Err(AuthVerifyError::IssuerNotAccepted {
                issuer: self.config.issuer.clone(),
            });
        }

        let mut payload_buf: StackJwtPayloadBuf = [0_u8; 4096];
        let mut payload_heap = Vec::new();
        let payload_bytes =
            decode_jwt_segment(parts.payload_b64, &mut payload_buf, &mut payload_heap)?;
        let probe: UnverifiedIssuerProbe<'_> = serde_json::from_slice(payload_bytes)
            .map_err(|_err| AuthVerifyError::MalformedToken)?;
        if probe.iss.is_empty() {
            return Err(AuthVerifyError::MalformedToken);
        }

        let issuer_ref = probe.iss.as_ref();
        if issuer_ref.trim_end_matches('/') == self.config.issuer {
            return Err(AuthVerifyError::IssuerNotAccepted {
                issuer: probe.iss.into_owned(),
            });
        }
        let Some(cache) = self.login_caches.get(issuer_ref) else {
            return Err(AuthVerifyError::IssuerNotAccepted {
                issuer: probe.iss.into_owned(),
            });
        };

        if let Some(cached) = cache.get_cached_key(kid) {
            match self.verify_and_parse_login_payload(
                parts,
                header.alg,
                Some(payload_bytes),
                cache,
                &cached,
            ) {
                Ok(caller) => return Ok(FastVerifyOutcome::Login(caller)),
                Err(LoginDecodeFailure::MalformedToken) => {
                    return Err(AuthVerifyError::MalformedToken);
                }
                Err(LoginDecodeFailure::InvalidClaims) => {
                    return Err(AuthVerifyError::InvalidToken);
                }
                Err(LoginDecodeFailure::MissingIdentity) => {
                    return Err(AuthVerifyError::MissingIdentity);
                }
                Err(LoginDecodeFailure::SignatureOrAlgorithm) => {
                    return Ok(FastVerifyOutcome::NeedsAsyncLogin {
                        alg: header.alg,
                        kid: kid.to_owned(),
                        issuer: cache.issuer.clone(),
                        used_cached_jwk: Some(cached.jwk.clone()),
                    });
                }
            }
        }

        Ok(FastVerifyOutcome::NeedsAsyncLogin {
            alg: header.alg,
            kid: kid.to_owned(),
            issuer: cache.issuer.clone(),
            used_cached_jwk: None,
        })
    }

    /// Cold JWKS cache-miss or key-rotation path for login tokens.
    /// Boxed by [`Self::verify_login_token`] and [`Self::verify_any_token`] so cached-key futures stay small.
    #[lore_macro::test_pub]
    async fn verify_login_token_slow(
        &self,
        parts: &SplitJwt<'_>,
        alg: Algorithm,
        kid: String,
        issuer: String,
        used_cached_jwk: Option<Jwk>,
    ) -> Result<CallerClaims, AuthVerifyError> {
        let Some(cache) = self.login_caches.get(&issuer) else {
            return Err(AuthVerifyError::IssuerNotAccepted { issuer });
        };

        let key = if let Some(ref prior_jwk) = used_cached_jwk {
            cache
                .refresh_if_changed(&kid, prior_jwk)
                .await?
                .ok_or(AuthVerifyError::InvalidToken)?
        } else {
            cache.get_key(&kid).await?
        };

        match self.verify_and_parse_login_payload(parts, alg, None, cache, &key) {
            Ok(caller) => Ok(caller),
            Err(LoginDecodeFailure::SignatureOrAlgorithm) if used_cached_jwk.is_none() => {
                let Some(rotated) = cache.refresh_if_changed(&kid, &key.jwk).await? else {
                    return Err(AuthVerifyError::InvalidToken);
                };
                match self.verify_and_parse_login_payload(parts, alg, None, cache, &rotated) {
                    Ok(caller) => Ok(caller),
                    Err(LoginDecodeFailure::MalformedToken) => Err(AuthVerifyError::MalformedToken),
                    Err(
                        LoginDecodeFailure::SignatureOrAlgorithm
                        | LoginDecodeFailure::InvalidClaims,
                    ) => Err(AuthVerifyError::InvalidToken),
                    Err(LoginDecodeFailure::MissingIdentity) => {
                        Err(AuthVerifyError::MissingIdentity)
                    }
                }
            }
            Err(LoginDecodeFailure::MalformedToken) => Err(AuthVerifyError::MalformedToken),
            Err(LoginDecodeFailure::SignatureOrAlgorithm | LoginDecodeFailure::InvalidClaims) => {
                Err(AuthVerifyError::InvalidToken)
            }
            Err(LoginDecodeFailure::MissingIdentity) => Err(AuthVerifyError::MissingIdentity),
        }
    }

    fn verify_exchanged_parts(
        &self,
        parts: &SplitJwt<'_>,
        alg: Algorithm,
        kid: Option<&str>,
    ) -> Result<VerifiedExchangedCaller, AuthVerifyError> {
        let kid = kid.ok_or(AuthVerifyError::MissingKeyId)?;
        if kid != self.signer.kid() {
            return Err(AuthVerifyError::UnknownSigningKey {
                issuer: self.config.issuer.clone(),
                kid: kid.to_owned(),
            });
        }
        if alg != Algorithm::ES256 {
            return Err(AuthVerifyError::InvalidToken);
        }

        let sig_ok = jsonwebtoken::crypto::verify(
            parts.signature_b64,
            parts.signing_input,
            self.signer.decoding_key(),
            Algorithm::ES256,
        )
        .map_err(|_err| AuthVerifyError::InvalidToken)?;
        if !sig_ok {
            return Err(AuthVerifyError::InvalidToken);
        }

        let mut payload_buf = [0_u8; 2048];
        let mut payload_heap = Vec::new();
        let payload_bytes =
            decode_jwt_segment(parts.payload_b64, &mut payload_buf, &mut payload_heap)
                .map_err(|_err| AuthVerifyError::InvalidToken)?;
        let now_secs = crate::http::unix_timestamp_secs();
        crate::policy::deserialize_and_validate_exchanged_claims(
            payload_bytes,
            &self.config.issuer,
            std::slice::from_ref(&self.config.audience),
            &self.config.resource_id_template,
            self.config.authentik.user_id_field,
            now_secs,
            JWT_CLOCK_SKEW_LEEWAY_SECS,
        )
    }

    fn verify_and_parse_login_payload(
        &self,
        parts: &SplitJwt<'_>,
        alg: Algorithm,
        predecoded_payload: Option<&[u8]>,
        cache: &IssuerKeyCache,
        cached: &CachedKey,
    ) -> Result<CallerClaims, LoginDecodeFailure> {
        if alg != cached.algorithm {
            return Err(LoginDecodeFailure::SignatureOrAlgorithm);
        }
        match jsonwebtoken::crypto::verify(
            parts.signature_b64,
            parts.signing_input,
            &cached.decoding_key,
            cached.algorithm,
        ) {
            Ok(true) => {}
            Ok(false) => {
                debug!(issuer = %cache.issuer, "login token failed JWT signature verification");
                return Err(LoginDecodeFailure::SignatureOrAlgorithm);
            }
            Err(err) => {
                debug!(issuer = %cache.issuer, ?err, "login token signature decode failed");
                return Err(match err.kind() {
                    ErrorKind::InvalidSignature | ErrorKind::InvalidAlgorithm => {
                        LoginDecodeFailure::SignatureOrAlgorithm
                    }
                    _ => LoginDecodeFailure::InvalidClaims,
                });
            }
        }

        if let Some(bytes) = predecoded_payload {
            return self.parse_verified_login_payload(bytes, cache);
        }

        let mut payload_buf: StackJwtPayloadBuf = [0_u8; 4096];
        let mut payload_heap = Vec::new();
        let payload_bytes =
            decode_jwt_segment(parts.payload_b64, &mut payload_buf, &mut payload_heap)
                .map_err(|_err| LoginDecodeFailure::MalformedToken)?;
        self.parse_verified_login_payload(payload_bytes, cache)
    }

    fn parse_verified_login_payload(
        &self,
        payload_bytes: &[u8],
        cache: &IssuerKeyCache,
    ) -> Result<CallerClaims, LoginDecodeFailure> {
        let now_secs = crate::http::unix_timestamp_secs();
        let raw = crate::policy::deserialize_and_validate_login_claims(
            payload_bytes,
            &self.config.policy.claims_key,
            &cache.issuer,
            &cache.login_audiences,
            now_secs,
            JWT_CLOCK_SKEW_LEEWAY_SECS,
        )
        .map_err(|()| LoginDecodeFailure::InvalidClaims)?;

        CallerClaims::from_login_claims_with_policy(
            raw,
            &self.config.projects,
            self.config.authentik.user_id_field,
            &self.config.policy,
        )
        .ok_or(LoginDecodeFailure::MissingIdentity)
    }

    /// Queries `authentik` `/api/v3/core/users/` by configured user ID (`username` or `uuid`),
    /// including deactivated accounts.
    pub async fn lookup_authentik_user_by_id(
        &self,
        user_id: &str,
    ) -> Result<Option<UserRecord>, AuthentikDirectoryError> {
        let (Some(base_url), Some(api_token)) = (
            self.authentik_base_url.as_ref(),
            self.config.authentik.api_token.as_deref(),
        ) else {
            return Ok(None);
        };
        if !is_valid_directory_query(user_id, MAX_USER_ID_BYTES) {
            return Ok(None);
        }

        if self.config.authentik.user_id_field == UserIdField::Uuid {
            let Some(canonical_id) = canonicalize_uuid(user_id) else {
                return Ok(None);
            };
            let canonical_ref = canonical_id.as_ref();
            if self.is_negatively_cached_user(NegativeLookup::Id, canonical_ref) {
                return Ok(None);
            }
            let mut endpoint = build_api_endpoint(base_url, "/api/v3/core/users/")
                .ok_or(AuthentikDirectoryError::Unavailable)?;
            endpoint
                .query_pairs_mut()
                .append_pair("uuid", canonical_ref);

            let users = self
                .fetch_authentik_users(endpoint, api_token, false, |id, _, _| id == canonical_ref)
                .await?;
            let found = users.into_iter().next();
            if let Some(ref user) = found {
                self.evict_negative_user_record(user);
            } else {
                self.record_negative_user(NegativeLookup::Id, canonical_ref);
            }
            return Ok(found);
        }

        if self.is_negatively_cached_user(NegativeLookup::Id, user_id) {
            return Ok(None);
        }

        let mut endpoint = build_api_endpoint(base_url, "/api/v3/core/users/")
            .ok_or(AuthentikDirectoryError::Unavailable)?;
        endpoint.query_pairs_mut().append_pair("username", user_id);

        let users = self
            .fetch_authentik_users(endpoint, api_token, false, |id, _, _| id == user_id)
            .await?;
        let found = users.into_iter().next();
        if let Some(ref user) = found {
            self.evict_negative_user_record(user);
        } else {
            self.record_negative_user(NegativeLookup::Id, user_id);
        }
        Ok(found)
    }

    /// Queries `authentik` `/api/v3/core/users/` by exact `username` regardless of `user_id_field`.
    pub async fn lookup_authentik_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserRecord>, AuthentikDirectoryError> {
        self.lookup_authentik_user_by_username_opts(username, false)
            .await
    }

    /// Queries `authentik` `/api/v3/core/users/` by exact `username`, bypassing any negative-cache
    /// entry so an unconfirmed OIDC-verified username claim is validated live against `authentik`.
    pub async fn lookup_authentik_user_by_username_live(
        &self,
        username: &str,
    ) -> Result<Option<UserRecord>, AuthentikDirectoryError> {
        self.lookup_authentik_user_by_username_opts(username, true)
            .await
    }

    async fn lookup_authentik_user_by_username_opts(
        &self,
        username: &str,
        bypass_negative_cache: bool,
    ) -> Result<Option<UserRecord>, AuthentikDirectoryError> {
        let (Some(base_url), Some(api_token)) = (
            self.authentik_base_url.as_ref(),
            self.config.authentik.api_token.as_deref(),
        ) else {
            return Ok(None);
        };
        if !is_valid_directory_query(username, MAX_USERNAME_BYTES) {
            return Ok(None);
        }
        if !bypass_negative_cache
            && self.is_negatively_cached_user(NegativeLookup::Username, username)
        {
            return Ok(None);
        }

        let mut endpoint = build_api_endpoint(base_url, "/api/v3/core/users/")
            .ok_or(AuthentikDirectoryError::Unavailable)?;
        endpoint.query_pairs_mut().append_pair("username", username);

        let users = self
            .fetch_authentik_users(endpoint, api_token, false, |_, uname, _| uname == username)
            .await?;
        let found = users.into_iter().next();
        if let Some(ref user) = found {
            self.evict_negative_user_record(user);
        } else {
            self.record_negative_user(NegativeLookup::Username, username);
        }
        Ok(found)
    }

    /// Queries `authentik` `/api/v3/core/users/` by exact display name (`?name=`).
    pub async fn lookup_authentik_users_by_display_name(
        &self,
        display_name: &str,
    ) -> Result<Vec<UserRecord>, AuthentikDirectoryError> {
        let (Some(base_url), Some(api_token)) = (
            self.authentik_base_url.as_ref(),
            self.config.authentik.api_token.as_deref(),
        ) else {
            return Ok(Vec::new());
        };
        if !is_valid_directory_query(display_name, MAX_DISPLAY_NAME_BYTES)
            || self.is_negatively_cached_user(NegativeLookup::DisplayName, display_name)
        {
            return Ok(Vec::new());
        }

        let mut endpoint = build_api_endpoint(base_url, "/api/v3/core/users/")
            .ok_or(AuthentikDirectoryError::Unavailable)?;
        endpoint
            .query_pairs_mut()
            .append_pair("name", display_name)
            .append_pair("page_size", "100");

        let matched = self
            .fetch_authentik_users(endpoint, api_token, true, |_, _, disp| disp == display_name)
            .await?;
        if matched.is_empty() {
            self.record_negative_user(NegativeLookup::DisplayName, display_name);
        } else {
            for user in &matched {
                self.evict_negative_user_record(user);
            }
        }
        Ok(matched)
    }

    /// Returns a fresh snapshot of `authentik` `/api/v3/core/groups/` project visibilities,
    /// or `Ok(None)` when `authentik` Core API queries are not configured.
    pub async fn refresh_group_visibilities(
        &self,
    ) -> Result<Option<Arc<HashMap<String, ProjectVisibility>>>, AuthentikDirectoryError> {
        let Some(base_url) = self.authentik_base_url.as_ref() else {
            return Ok(None);
        };
        let Some(api_token) = self.config.authentik.api_token.as_deref() else {
            return Ok(None);
        };

        if let Some(cached) = self.cached_group_map() {
            return cached.map(Some);
        }

        let _gate = self.group_cache.refresh_gate.lock().await;
        if let Some(cached) = self.cached_group_map() {
            return cached.map(Some);
        }

        if let Ok(fresh_projects) = self
            .fetch_authentik_project_visibilities(base_url, api_token)
            .await
        {
            let shared = Arc::new(fresh_projects);
            let now = Instant::now();
            let mut guard = self.group_cache.state.write();
            guard.projects = Arc::clone(&shared);
            guard.last_attempt = Some(now);
            guard.last_success = Some(now);
            guard.last_refresh_failed = false;
            #[cfg(feature = "test-util")]
            {
                guard.force_expired = false;
            }
            Ok(Some(shared))
        } else {
            let mut guard = self.group_cache.state.write();
            guard.last_attempt = Some(Instant::now());
            guard.last_refresh_failed = true;
            Err(AuthentikDirectoryError::Unavailable)
        }
    }

    fn cached_group_map(
        &self,
    ) -> Option<Result<Arc<HashMap<String, ProjectVisibility>>, AuthentikDirectoryError>> {
        let guard = self.group_cache.state.read();
        #[cfg(feature = "test-util")]
        let expired_override = guard.force_expired;
        #[cfg(not(feature = "test-util"))]
        let expired_override = false;

        let fresh = !expired_override
            && guard
                .last_success
                .is_some_and(|at| at.elapsed() < GROUP_CACHE_TTL);
        if fresh {
            return Some(Ok(Arc::clone(&guard.projects)));
        }

        let min_interval = if guard.last_success.is_some() {
            MIN_REFRESH_INTERVAL
        } else {
            INITIAL_RETRY_INTERVAL
        };
        if guard
            .last_attempt
            .is_some_and(|at| at.elapsed() < min_interval)
        {
            return Some(Err(AuthentikDirectoryError::Unavailable));
        }
        None
    }

    /// Queries `authentik` `/api/v3/core/groups/` (through a single-flight TTL cache) to determine
    /// whether `project` exists and its fail-closed visibility.
    pub async fn lookup_authentik_project_visibility(
        &self,
        project: &str,
    ) -> AuthentikProjectLookup {
        let Some(base_url) = self.authentik_base_url.as_ref() else {
            return AuthentikProjectLookup::NotConfigured;
        };
        let Some(api_token) = self.config.authentik.api_token.as_deref() else {
            return AuthentikProjectLookup::NotConfigured;
        };

        let trimmed = project.trim();
        let normalized: Cow<'_, str> = if !trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Borrowed(trimmed)
        } else {
            Cow::Owned(trimmed.to_ascii_lowercase())
        };
        if let Some(cached) = self.cached_project_lookup(normalized.as_ref()) {
            return cached;
        }

        let _gate = self.group_cache.refresh_gate.lock().await;
        if let Some(cached) = self.cached_project_lookup(normalized.as_ref()) {
            return cached;
        }

        if let Ok(fresh_projects) = self
            .fetch_authentik_project_visibilities(base_url, api_token)
            .await
        {
            let resolved = fresh_projects.get(normalized.as_ref()).copied();
            let now = Instant::now();
            let mut guard = self.group_cache.state.write();
            guard.projects = Arc::new(fresh_projects);
            guard.last_attempt = Some(now);
            guard.last_success = Some(now);
            guard.last_refresh_failed = false;
            #[cfg(feature = "test-util")]
            {
                guard.force_expired = false;
            }
            match resolved {
                Some(vis) => AuthentikProjectLookup::Found(vis),
                None => AuthentikProjectLookup::NotFound,
            }
        } else {
            let mut guard = self.group_cache.state.write();
            guard.last_attempt = Some(Instant::now());
            guard.last_refresh_failed = true;
            AuthentikProjectLookup::Unavailable
        }
    }

    fn cached_project_lookup(&self, normalized_project: &str) -> Option<AuthentikProjectLookup> {
        let guard = self.group_cache.state.read();
        #[cfg(feature = "test-util")]
        let expired_override = guard.force_expired;
        #[cfg(not(feature = "test-util"))]
        let expired_override = false;

        let fresh = !expired_override
            && guard
                .last_success
                .is_some_and(|at| at.elapsed() < GROUP_CACHE_TTL);
        if fresh {
            if let Some(&vis) = guard.projects.get(normalized_project) {
                return Some(AuthentikProjectLookup::Found(vis));
            }
            if guard
                .last_attempt
                .is_some_and(|at| at.elapsed() < MIN_REFRESH_INTERVAL)
            {
                return Some(if guard.last_refresh_failed {
                    AuthentikProjectLookup::Unavailable
                } else {
                    AuthentikProjectLookup::NotFound
                });
            }
            return None;
        }

        let min_interval = if guard.last_success.is_some() {
            MIN_REFRESH_INTERVAL
        } else {
            INITIAL_RETRY_INTERVAL
        };
        if guard
            .last_attempt
            .is_some_and(|at| at.elapsed() < min_interval)
        {
            return Some(AuthentikProjectLookup::Unavailable);
        }
        None
    }

    async fn fetch_authentik_project_visibilities(
        &self,
        base_url: &url::Url,
        api_token: &str,
    ) -> Result<HashMap<String, ProjectVisibility>, ()> {
        #[derive(Deserialize)]
        struct AuthentikGroupAttributes {
            #[serde(default, deserialize_with = "crate::policy::present_string_claim")]
            lore_project: Option<PresentStringClaim>,
            #[serde(
                default = "default_internal_visibility",
                deserialize_with = "deserialize_group_visibility"
            )]
            lore_visibility: ProjectVisibility,
        }
        #[derive(Deserialize)]
        struct AuthentikGroupItem {
            #[serde(default)]
            attributes: Option<AuthentikGroupAttributes>,
        }
        #[derive(Deserialize)]
        struct AuthentikGroupPage {
            #[serde(default)]
            pagination: Option<AuthentikPagination>,
            results: Vec<AuthentikGroupItem>,
        }

        let mut projects = HashMap::new();
        let mut page_number: u64 = 1;
        let mut completed_all_pages = false;

        for _ in 0..MAX_GROUP_PAGES {
            let mut endpoint = build_api_endpoint(base_url, "/api/v3/core/groups/").ok_or(())?;
            endpoint
                .query_pairs_mut()
                .append_pair("include_users", "false")
                .append_pair("page_size", "100")
                .append_pair("page", &page_number.to_string());

            let mut response = self
                .http_client
                .get(endpoint)
                .bearer_auth(api_token)
                .send()
                .await
                .map_err(|err| {
                    warn!(?err, "authentik group visibility request failed");
                })?;
            if !response.status().is_success() {
                warn!(
                    status = %response.status().as_u16(),
                    "authentik group visibility lookup returned non-success"
                );
                return Err(());
            }
            let body = read_capped_body("authentik groups", &mut response)
                .await
                .map_err(|reason| {
                    warn!(%reason, "failed reading authentik group visibility response");
                })?;
            let page: AuthentikGroupPage = serde_json::from_str(&body).map_err(|err| {
                warn!(?err, "invalid JSON in authentik group visibility response");
            })?;

            for group in &page.results {
                let Some(attrs) = &group.attributes else {
                    continue;
                };
                let Some(PresentStringClaim::Valid(raw_slug)) = &attrs.lore_project else {
                    continue;
                };
                let trimmed = raw_slug.trim();
                if trimmed.len() > crate::policy::MAX_PROJECT_SLUG_BYTES {
                    continue;
                }
                let slug = trimmed.to_ascii_lowercase();
                if !crate::policy::is_valid_project_slug(&slug) {
                    continue;
                }
                let vis = attrs.lore_visibility;
                projects
                    .entry(slug)
                    .and_modify(|cur: &mut ProjectVisibility| *cur = cur.merge(vis))
                    .or_insert(vis);
            }

            match page.pagination.and_then(|pag| pag.next) {
                Some(next) if next > page_number => {
                    page_number = next;
                }
                _ => {
                    completed_all_pages = true;
                    break;
                }
            }
        }

        if !completed_all_pages {
            warn!(
                max_pages = MAX_GROUP_PAGES,
                "authentik group visibility lookup exceeded maximum pagination limit"
            );
            return Err(());
        }

        Ok(projects)
    }

    async fn fetch_authentik_users(
        &self,
        base_endpoint: url::Url,
        api_token: &str,
        paginate: bool,
        mut accept: impl FnMut(&str, &str, &str) -> bool,
    ) -> Result<Vec<UserRecord>, AuthentikDirectoryError> {
        #[derive(Deserialize)]
        struct AuthentikUserItem {
            #[serde(default)]
            username: Option<String>,
            #[serde(default)]
            uuid: Option<String>,
            #[serde(default)]
            name: Option<String>,
        }
        #[derive(Deserialize)]
        struct AuthentikUserPage {
            #[serde(default)]
            pagination: Option<AuthentikPagination>,
            results: Vec<AuthentikUserItem>,
        }

        let use_uuid = self.config.authentik.user_id_field == UserIdField::Uuid;
        let max_pages = if paginate { MAX_DISPLAY_NAME_PAGES } else { 1 };
        let mut collected = Vec::new();
        let mut page_number: u64 = 1;
        let mut completed = false;

        for _ in 0..max_pages {
            let mut endpoint = base_endpoint.clone();
            if paginate {
                endpoint
                    .query_pairs_mut()
                    .append_pair("page", &page_number.to_string());
            }

            let mut response = self
                .http_client
                .get(endpoint)
                .bearer_auth(api_token)
                .send()
                .await
                .map_err(|err| {
                    warn!(?err, "authentik user directory request failed");
                    AuthentikDirectoryError::Unavailable
                })?;
            if !response.status().is_success() {
                warn!(
                    status = %response.status().as_u16(),
                    "authentik user directory lookup returned non-success"
                );
                return Err(AuthentikDirectoryError::Unavailable);
            }
            let body = read_capped_body("authentik users", &mut response)
                .await
                .map_err(|reason| {
                    warn!(%reason, "failed reading authentik user directory response");
                    AuthentikDirectoryError::Unavailable
                })?;
            let page: AuthentikUserPage = serde_json::from_str(&body).map_err(|err| {
                warn!(?err, "invalid JSON in authentik user directory response");
                AuthentikDirectoryError::Unavailable
            })?;

            for item in page.results {
                let username = item.username.unwrap_or_default();
                if !is_valid_directory_query(&username, MAX_USERNAME_BYTES) {
                    continue;
                }
                let uuid = item.uuid.unwrap_or_default();
                let name = item
                    .name
                    .filter(|val| is_valid_directory_query(val, MAX_DISPLAY_NAME_BYTES))
                    .unwrap_or_default();
                let canonical_id: Cow<'_, str> = if use_uuid {
                    let Some(canon) = canonicalize_uuid(&uuid) else {
                        continue;
                    };
                    canon
                } else {
                    Cow::Borrowed(username.as_str())
                };
                let display_ref = if name.is_empty() {
                    username.as_str()
                } else {
                    name.as_str()
                };
                if !accept(canonical_id.as_ref(), username.as_str(), display_ref) {
                    continue;
                }
                let id = canonical_id.into_owned();
                let display_name = if name.is_empty() {
                    username.clone()
                } else {
                    name
                };
                collected.push(UserRecord {
                    id,
                    username,
                    display_name,
                });
            }

            if !paginate {
                completed = true;
                break;
            }
            match page.pagination.and_then(|pag| pag.next) {
                Some(next) if next > page_number => {
                    page_number = next;
                }
                _ => {
                    completed = true;
                    break;
                }
            }
        }

        if !completed {
            warn!(
                max_pages = MAX_DISPLAY_NAME_PAGES,
                "authentik user directory lookup exceeded maximum pagination limit"
            );
            return Err(AuthentikDirectoryError::Unavailable);
        }

        Ok(collected)
    }

    /// Filters `ids` in place, removing entries currently recorded as recent `UserGet` misses.
    pub(crate) fn retain_not_negatively_cached_user_ids(&self, ids: &mut Vec<String>) {
        let now = Instant::now();
        let mut cache = self.negative_user_cache.lock();
        ids.retain(|id| !cache.by_id.contains_fresh(id, now, NEGATIVE_USER_CACHE_TTL));
    }

    /// Acquires a bounded cooldown slot for `(identity, username)` so replaying a stale UUID
    /// token cannot trigger repeated upstream `authentik` user lookups.
    pub(crate) fn try_acquire_conflict_resolution_slot(
        &self,
        identity: &str,
        username: &str,
    ) -> bool {
        if !is_valid_directory_query(identity, MAX_USER_ID_BYTES)
            || !is_valid_directory_query(username, MAX_USERNAME_BYTES)
        {
            return false;
        }
        let mut key_buf = [0_u8; MAX_USER_ID_BYTES + 1 + MAX_USERNAME_BYTES];
        let total_len = identity.len() + 1 + username.len();
        if total_len > key_buf.len() {
            return false;
        }
        key_buf[..identity.len()].copy_from_slice(identity.as_bytes());
        key_buf[identity.len()] = b'\0';
        key_buf[identity.len() + 1..total_len].copy_from_slice(username.as_bytes());
        let Ok(composite_key) = std::str::from_utf8(&key_buf[..total_len]) else {
            return false;
        };

        let now = Instant::now();
        let mut cache = self.negative_user_cache.lock();
        if cache
            .conflict_cooldown
            .contains_fresh(composite_key, now, CONFLICT_RESOLUTION_COOLDOWN)
        {
            return false;
        }
        cache.clock = cache.clock.wrapping_add(1);
        let seq = cache.clock;
        cache.conflict_cooldown.record(composite_key, now, seq);
        true
    }

    fn is_negatively_cached_user(&self, kind: NegativeLookup, key: &str) -> bool {
        let now = Instant::now();
        let mut cache = self.negative_user_cache.lock();
        let bucket = match kind {
            NegativeLookup::Id => &mut cache.by_id,
            NegativeLookup::Username => &mut cache.by_username,
            NegativeLookup::DisplayName => &mut cache.by_display_name,
        };
        bucket.contains_fresh(key, now, NEGATIVE_USER_CACHE_TTL)
    }

    fn evict_negative_user_record(&self, user: &UserRecord) {
        let mut cache = self.negative_user_cache.lock();
        cache.by_id.remove(&user.id);
        if !user.username.is_empty() {
            cache.by_username.remove(&user.username);
        }
        if !user.display_name.is_empty() {
            cache.by_display_name.remove(&user.display_name);
        }
    }

    fn record_negative_user(&self, kind: NegativeLookup, key: &str) {
        let now = Instant::now();
        let mut cache = self.negative_user_cache.lock();
        cache.clock = cache.clock.wrapping_add(1);
        let seq = cache.clock;
        let bucket = match kind {
            NegativeLookup::Id => &mut cache.by_id,
            NegativeLookup::Username => &mut cache.by_username,
            NegativeLookup::DisplayName => &mut cache.by_display_name,
        };
        bucket.record(key, now, seq);
    }
}

#[derive(Deserialize)]
struct AuthentikPagination {
    #[serde(default)]
    next: Option<u64>,
}

const fn default_internal_visibility() -> ProjectVisibility {
    ProjectVisibility::Internal
}

fn deserialize_group_visibility<'de, D>(deserializer: D) -> Result<ProjectVisibility, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct GroupVisibilityVisitor;

    impl<'de> serde::de::Visitor<'de> for GroupVisibilityVisitor {
        type Value = ProjectVisibility;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an optional visibility value")
        }

        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(ProjectVisibility::Internal)
        }

        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(ProjectVisibility::Internal)
        }

        fn visit_some<D2>(self, deserializer: D2) -> Result<Self::Value, D2::Error>
        where
            D2: serde::Deserializer<'de>,
        {
            deserializer.deserialize_any(self)
        }

        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(crate::policy::parse_claim_visibility(Some(v)))
        }

        fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
            Ok(ProjectVisibility::Restricted)
        }

        fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
            Ok(ProjectVisibility::Restricted)
        }

        fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
            Ok(ProjectVisibility::Restricted)
        }

        fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
            Ok(ProjectVisibility::Restricted)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
            Ok(ProjectVisibility::Restricted)
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            while map
                .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                .is_some()
            {}
            Ok(ProjectVisibility::Restricted)
        }
    }

    deserializer.deserialize_any(GroupVisibilityVisitor)
}

impl IssuerKeyCache {
    fn get_cached_key(&self, kid: &str) -> Option<Arc<CachedKey>> {
        self.state.read().keys.get(kid).cloned()
    }

    async fn get_key(&self, kid: &str) -> Result<Arc<CachedKey>, AuthVerifyError> {
        if let Some(hit) = self.get_cached_key(kid) {
            return Ok(hit);
        }

        self.refresh(Some(kid)).await?;

        let guard = self.state.read();
        if let Some(hit) = guard.keys.get(kid) {
            return Ok(Arc::clone(hit));
        }
        if guard.last_success.is_none() || guard.last_refresh_failed {
            return Err(AuthVerifyError::ProviderUnavailable {
                issuer: self.issuer.clone(),
            });
        }
        Err(AuthVerifyError::UnknownSigningKey {
            issuer: self.issuer.clone(),
            kid: kid.to_owned(),
        })
    }

    async fn refresh_if_changed(
        &self,
        kid: &str,
        used_jwk: &Jwk,
    ) -> Result<Option<Arc<CachedKey>>, AuthVerifyError> {
        {
            let guard = self.state.read();
            if let Some(entry) = guard.keys.get(kid)
                && entry.jwk != *used_jwk
            {
                return Ok(Some(Arc::clone(entry)));
            }
        }
        self.refresh(None).await?;
        let guard = self.state.read();
        match guard.keys.get(kid) {
            Some(entry) if entry.jwk != *used_jwk => Ok(Some(Arc::clone(entry))),
            _ => Ok(None),
        }
    }

    async fn refresh(&self, desired_kid: Option<&str>) -> Result<(), AuthVerifyError> {
        if self.can_skip_refresh(desired_kid) {
            return Ok(());
        }

        let _gate = self.refresh_gate.lock().await;
        if self.can_skip_refresh(desired_kid) {
            return Ok(());
        }

        match self.fetch_keys().await {
            Ok((fresh_keys, resolved_jwks_url, rediscovered)) => {
                let mut guard = self.state.write();
                guard.keys = fresh_keys;
                guard.jwks_url = Some(resolved_jwks_url);
                let now = Instant::now();
                if rediscovered || guard.jwks_url_discovered_at.is_none() {
                    guard.jwks_url_discovered_at = Some(now);
                }
                guard.last_attempt = Some(now);
                guard.last_success = Some(now);
                guard.last_refresh_failed = false;
                Ok(())
            }
            Err(reason) => {
                warn!(issuer = %self.issuer, %reason, "failed to refresh login issuer JWKS");
                let mut guard = self.state.write();
                guard.last_attempt = Some(Instant::now());
                guard.last_refresh_failed = true;
                if !guard.keys.is_empty() {
                    Ok(())
                } else {
                    Err(AuthVerifyError::ProviderUnavailable {
                        issuer: self.issuer.clone(),
                    })
                }
            }
        }
    }

    fn can_skip_refresh(&self, desired_kid: Option<&str>) -> bool {
        let guard = self.state.read();
        if let Some(kid) = desired_kid
            && guard.keys.contains_key(kid)
        {
            return true;
        }
        let min_interval = if guard.last_success.is_some() {
            MIN_REFRESH_INTERVAL
        } else {
            INITIAL_RETRY_INTERVAL
        };
        guard
            .last_attempt
            .is_some_and(|at| at.elapsed() < min_interval)
    }

    async fn fetch_keys(
        &self,
    ) -> Result<(HashMap<String, Arc<CachedKey>>, url::Url, bool), String> {
        let cached_url = {
            let guard = self.state.read();
            guard
                .jwks_url_discovered_at
                .filter(|at| at.elapsed() < DISCOVERY_URL_TTL)
                .and_then(|_| guard.jwks_url.clone())
        };
        if let Some(jwks_url) = cached_url {
            match self.fetch_jwks_keys(jwks_url.clone()).await {
                Ok(keys) => return Ok((keys, jwks_url, false)),
                Err(JwksFetchError::EndpointMissing) => {}
                Err(JwksFetchError::Other(reason)) => return Err(reason),
            }
        }

        let jwks_url = self.discover_jwks_url().await?;
        let keys = self
            .fetch_jwks_keys(jwks_url.clone())
            .await
            .map_err(JwksFetchError::into_reason)?;
        Ok((keys, jwks_url, true))
    }

    async fn discover_jwks_url(&self) -> Result<url::Url, String> {
        let configured_issuer = self
            .configured_issuer
            .as_ref()
            .ok_or_else(|| format!("invalid configured issuer URL '{}'", self.issuer))?;
        let discovery_url = self
            .discovery_url
            .clone()
            .ok_or_else(|| format!("invalid discovery URL for issuer '{}'", self.issuer))?;

        let mut discovery_resp = self
            .client
            .get(discovery_url)
            .send()
            .await
            .map_err(|err| format!("discovery request failed: {err}"))?;
        if !discovery_resp.status().is_success() {
            return Err(format!(
                "discovery answered HTTP {}",
                discovery_resp.status().as_u16()
            ));
        }
        let discovery_body = read_capped_body("OIDC discovery", &mut discovery_resp).await?;
        let discovery: OidcDiscoveryDocument = serde_json::from_str(&discovery_body)
            .map_err(|err| format!("invalid OIDC discovery JSON: {err}"))?;

        let discovery_issuer = crate::config::parse_clean_http_url(&discovery.issuer, false)?;
        let issuer_matches = match &self.provider_url {
            None => discovery.issuer == self.issuer,
            Some(provider) => {
                discovery.issuer == self.issuer
                    || rewrite_origin_issuer_str(&self.issuer, provider)
                        .is_some_and(|rewritten| discovery.issuer == rewritten)
            }
        };
        if !issuer_matches {
            return Err(format!(
                "discovery issuer '{}' mismatches configured issuer '{}'",
                discovery.issuer, self.issuer
            ));
        }

        let jwks_parsed = crate::config::parse_clean_http_url(&discovery.jwks_uri, true)?;
        let jwks_origin_valid = jwks_parsed.origin() == configured_issuer.origin()
            || jwks_parsed.origin() == discovery_issuer.origin();
        if !jwks_origin_valid {
            return Err(format!(
                "refusing off-origin jwks_uri '{}' for issuer '{}'",
                discovery.jwks_uri, self.issuer
            ));
        }
        if configured_issuer.scheme() == "https" && jwks_parsed.scheme() != "https" {
            let allowed_mesh_override = self
                .provider_url
                .as_ref()
                .is_some_and(|provider| jwks_parsed.origin() == provider.origin());
            if !allowed_mesh_override {
                return Err(format!(
                    "refusing non-HTTPS jwks_uri '{}' for HTTPS issuer",
                    discovery.jwks_uri
                ));
            }
        }

        match &self.provider_url {
            Some(provider) if jwks_parsed.origin() == configured_issuer.origin() => {
                rewrite_origin_url(jwks_parsed, provider)
                    .ok_or_else(|| format!("cannot rewrite jwks_uri '{}'", discovery.jwks_uri))
            }
            _ => Ok(jwks_parsed),
        }
    }

    async fn fetch_jwks_keys(
        &self,
        jwks_url: url::Url,
    ) -> Result<HashMap<String, Arc<CachedKey>>, JwksFetchError> {
        let mut jwks_resp = self
            .client
            .get(jwks_url)
            .send()
            .await
            .map_err(|err| JwksFetchError::Other(format!("JWKS request failed: {err}")))?;
        let status = jwks_resp.status();
        if matches!(
            status,
            reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::GONE
        ) {
            return Err(JwksFetchError::EndpointMissing);
        }
        if !status.is_success() {
            return Err(JwksFetchError::Other(format!(
                "JWKS answered HTTP {}",
                status.as_u16()
            )));
        }
        let jwks_body = read_capped_body("JWKS", &mut jwks_resp)
            .await
            .map_err(JwksFetchError::Other)?;
        let jwks: JwkSet = serde_json::from_str(&jwks_body)
            .map_err(|err| JwksFetchError::Other(format!("invalid JWKS JSON: {err}")))?;

        let mut usable = HashMap::new();
        for jwk in jwks.keys.into_iter().take(MAX_KEYS_PER_ISSUER) {
            let Some(kid) = jwk.common.key_id.clone() else {
                continue;
            };
            let Some(algorithm) = asymmetric_signature_algorithm(&jwk) else {
                continue;
            };
            let Ok(decoding_key) = DecodingKey::from_jwk(&jwk) else {
                continue;
            };
            if !key_family_matches(&decoding_key, algorithm) {
                continue;
            };
            usable.insert(
                kid,
                Arc::new(CachedKey {
                    jwk,
                    decoding_key,
                    algorithm,
                }),
            );
        }

        if usable.is_empty() {
            return Err(JwksFetchError::Other(
                "JWKS carried no usable asymmetric verification keys".to_owned(),
            ));
        }
        Ok(usable)
    }
}

fn build_api_endpoint(base_url: &url::Url, suffix: &str) -> Option<url::Url> {
    let base_trimmed = base_url.as_str().trim_end_matches('/');
    url::Url::parse(&format!("{base_trimmed}{suffix}")).ok()
}

fn rewrite_origin_url(mut target: url::Url, provider: &url::Url) -> Option<url::Url> {
    target.set_scheme(provider.scheme()).ok()?;
    target.set_host(provider.host_str()).ok()?;
    target.set_port(provider.port()).ok()?;
    Some(target)
}

fn rewrite_origin_issuer_str(raw_issuer: &str, provider: &url::Url) -> Option<String> {
    let (_, after_scheme) = raw_issuer.split_once("://")?;
    let path_suffix = match after_scheme.find('/') {
        Some(slash_idx) => &after_scheme[slash_idx..],
        None => "",
    };
    let provider_origin = provider.origin().ascii_serialization();
    if provider_origin == "null" {
        return None;
    }
    Some(format!("{provider_origin}{path_suffix}"))
}

/// Selects only asymmetric signing algorithms so a public JWK can never be
/// verified as a symmetric HMAC secret.
fn asymmetric_signature_algorithm(jwk: &Jwk) -> Option<Algorithm> {
    let declared = jwk.common.key_algorithm.or_else(|| {
        let is_rsa = matches!(jwk.algorithm, AlgorithmParameters::RSA(_));
        let use_ok = jwk
            .common
            .public_key_use
            .as_ref()
            .is_none_or(|u| matches!(u, PublicKeyUse::Signature));
        let ops_ok = jwk
            .common
            .key_operations
            .as_ref()
            .is_none_or(|ops| ops.iter().any(|op| matches!(op, KeyOperations::Verify)));
        (is_rsa && use_ok && ops_ok).then_some(KeyAlgorithm::RS256)
    })?;

    let alg = Algorithm::from_str(&declared.to_string()).ok()?;
    match alg {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512
        | Algorithm::ES256
        | Algorithm::ES384
        | Algorithm::EdDSA => Some(alg),
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => None,
    }
}

fn key_family_matches(key: &DecodingKey, algorithm: Algorithm) -> bool {
    !matches!(
        jsonwebtoken::crypto::verify("", b"", key, algorithm),
        Err(ref err) if *err.kind() == ErrorKind::InvalidAlgorithm
    )
}

/// Splits a compact JWS string into its signing input and three base64url segments.
#[lore_macro::test_pub]
fn split_jwt(token: &str) -> Result<SplitJwt<'_>, AuthVerifyError> {
    let first_dot = token.find('.').ok_or(AuthVerifyError::MalformedToken)?;
    let rest = &token[first_dot + 1..];
    let second_dot_rel = rest.find('.').ok_or(AuthVerifyError::MalformedToken)?;
    let second_dot = first_dot + 1 + second_dot_rel;
    let signature_b64 = &rest[second_dot_rel + 1..];
    if signature_b64.contains('.') {
        return Err(AuthVerifyError::MalformedToken);
    }
    let header_b64 = &token[..first_dot];
    let payload_b64 = &rest[..second_dot_rel];
    if header_b64.is_empty() || payload_b64.is_empty() {
        return Err(AuthVerifyError::MalformedToken);
    }
    Ok(SplitJwt {
        signing_input: &token.as_bytes()[..second_dot],
        header_b64,
        payload_b64,
        signature_b64,
    })
}

fn decode_jwt_segment<'a>(
    segment_b64: &str,
    stack_buf: &'a mut [u8],
    heap_fallback: &'a mut Vec<u8>,
) -> Result<&'a [u8], AuthVerifyError> {
    let max_decoded = base64::decoded_len_estimate(segment_b64.len());
    if max_decoded <= stack_buf.len() {
        let written = URL_SAFE_NO_PAD
            .decode_slice(segment_b64, stack_buf)
            .map_err(|_err| AuthVerifyError::MalformedToken)?;
        Ok(&stack_buf[..written])
    } else {
        heap_fallback.clear();
        URL_SAFE_NO_PAD
            .decode_vec(segment_b64, heap_fallback)
            .map_err(|_err| AuthVerifyError::MalformedToken)?;
        Ok(heap_fallback.as_slice())
    }
}

fn is_login_jwt_typ(typ: &str) -> bool {
    strip_application_prefix(typ).eq_ignore_ascii_case("jwt")
}

fn is_at_jwt_typ(typ: &str) -> bool {
    strip_application_prefix(typ).eq_ignore_ascii_case("at+jwt")
}

fn strip_application_prefix(typ: &str) -> &str {
    const PREFIX: &str = "application/";
    if typ.len() > PREFIX.len()
        && typ
            .get(..PREFIX.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(PREFIX))
    {
        &typ[PREFIX.len()..]
    } else {
        typ
    }
}

async fn read_capped_body(what: &str, response: &mut reqwest::Response) -> Result<String, String> {
    if let Some(declared) = response.content_length()
        && declared > u64::try_from(MAX_HTTP_RESPONSE_BYTES).unwrap_or(u64::MAX)
    {
        return Err(format!(
            "{what} declared {declared} bytes, exceeding {MAX_HTTP_RESPONSE_BYTES}"
        ));
    }

    let mut buf = Vec::new();
    loop {
        let chunk = response
            .chunk()
            .await
            .map_err(|err| format!("failed reading {what}: {err}"))?;
        let Some(bytes) = chunk else {
            break;
        };
        if buf.len().saturating_add(bytes.len()) > MAX_HTTP_RESPONSE_BYTES {
            return Err(format!(
                "{what} exceeded {MAX_HTTP_RESPONSE_BYTES} byte limit"
            ));
        }
        buf.extend_from_slice(&bytes);
    }

    String::from_utf8(buf).map_err(|err| format!("{what} is not valid UTF-8: {err}"))
}

/// Returns whether `raw` is non-empty, at most `max_bytes` bytes, and free of ASCII control characters.
pub(crate) fn is_valid_directory_query(raw: &str, max_bytes: usize) -> bool {
    !raw.is_empty() && raw.len() <= max_bytes && !raw.bytes().any(|b| b.is_ascii_control())
}

/// Normalizes a 32-char compact or 36-char hyphenated UUID to 36-char lowercase hyphenated form,
/// borrowing `raw` without allocation when it is already canonical.
pub(crate) fn canonicalize_uuid(raw: &str) -> Option<Cow<'_, str>> {
    if is_canonical_hyphenated_uuid(raw) {
        return Some(Cow::Borrowed(raw));
    }
    let bytes = parse_uuid_bytes(raw)?;
    let formatted = format_uuid_hyphenated(bytes);
    let text = std::str::from_utf8(&formatted).ok()?.to_owned();
    Some(Cow::Owned(text))
}

fn is_canonical_hyphenated_uuid(raw: &str) -> bool {
    if raw.len() != 36 {
        return false;
    }
    for (idx, b) in raw.bytes().enumerate() {
        if matches!(idx, 8 | 13 | 18 | 23) {
            if b != b'-' {
                return false;
            }
        } else if !matches!(b, b'0'..=b'9' | b'a'..=b'f') {
            return false;
        }
    }
    true
}

fn format_uuid_hyphenated(bytes: [u8; 16]) -> [u8; 36] {
    let mut out = [b'-'; 36];
    let _ = hex::encode_to_slice(&bytes[0..4], &mut out[0..8]);
    let _ = hex::encode_to_slice(&bytes[4..6], &mut out[9..13]);
    let _ = hex::encode_to_slice(&bytes[6..8], &mut out[14..18]);
    let _ = hex::encode_to_slice(&bytes[8..10], &mut out[19..23]);
    let _ = hex::encode_to_slice(&bytes[10..16], &mut out[24..36]);
    out
}

fn parse_uuid_bytes(raw: &str) -> Option<[u8; 16]> {
    let mut out = [0_u8; 16];
    match raw.len() {
        32 => {
            hex::decode_to_slice(raw, &mut out).ok()?;
            Some(out)
        }
        36 => {
            let bytes = raw.as_bytes();
            if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
                return None;
            }
            hex::decode_to_slice(&bytes[0..8], &mut out[0..4]).ok()?;
            hex::decode_to_slice(&bytes[9..13], &mut out[4..6]).ok()?;
            hex::decode_to_slice(&bytes[14..18], &mut out[6..8]).ok()?;
            hex::decode_to_slice(&bytes[19..23], &mut out[8..10]).ok()?;
            hex::decode_to_slice(&bytes[24..36], &mut out[10..16]).ok()?;
            Some(out)
        }
        _ => None,
    }
}

#[cfg(feature = "test-util")]
pub mod test_util {
    use super::TokenVerifier;

    impl TokenVerifier {
        /// Clears the per-issuer JWKS and group-visibility refresh backoff timestamps so tests run without sleeps.
        pub fn clear_refresh_backoff(&self) {
            for cache in self.login_caches.values() {
                cache.state.write().last_attempt = None;
            }
            self.group_cache.state.write().last_attempt = None;
        }

        /// Marks the cached `authentik` group visibility table as expired while keeping prior entries in memory.
        pub fn expire_group_cache_ttl(&self) {
            let mut guard = self.group_cache.state.write();
            guard.force_expired = true;
            guard.last_attempt = None;
        }

        /// Backdates `last_attempt` on the `authentik` group visibility cache without sleeping.
        pub fn backdate_group_attempt(&self, elapsed: std::time::Duration) {
            let backdated = std::time::Instant::now().checked_sub(elapsed);
            let mut guard = self.group_cache.state.write();
            if guard.last_attempt.is_some() {
                guard.last_attempt = backdated;
            }
        }

        /// Returns the number of project entries stored in the group visibility cache.
        pub fn cached_project_visibility_count(&self) -> usize {
            self.group_cache.state.read().projects.len()
        }

        /// Backdates `last_success` and `jwks_url_discovered_at` on all login `IssuerKeyCache`s and clears `last_attempt`.
        pub fn backdate_issuer_cache(&self, elapsed: std::time::Duration) {
            let backdated = std::time::Instant::now().checked_sub(elapsed);
            for cache in self.login_caches.values() {
                let mut guard = cache.state.write();
                if guard.last_success.is_some() {
                    guard.last_success = backdated;
                }
                if guard.jwks_url_discovered_at.is_some() {
                    guard.jwks_url_discovered_at = backdated;
                }
                guard.last_attempt = None;
            }
        }
    }
}

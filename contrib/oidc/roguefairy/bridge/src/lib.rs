// SPDX-FileCopyrightText: 2026 Rogue Fairy Studios
// SPDX-License-Identifier: MIT

pub mod config;
pub mod error;
pub mod grpc;
pub mod http;
pub mod jwks;
pub mod policy;
pub mod signing;
pub mod store;

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::http::HeaderMap;
use tonic::metadata::MetadataMap;

use crate::config::BridgeConfig;
use crate::grpc::GrpcBridgeService;
use crate::http::build_http_router;
use crate::http::serialize_openid_configuration;
use crate::jwks::AuthentikDirectoryError;
use crate::jwks::TokenVerifier;
use crate::policy::CallerClaims;
use crate::policy::ProjectVisibility;
use crate::policy::VerifiedCaller;
use crate::policy::caller_depends_on_project_visibility;
use crate::policy::resolve_configured_or_live_visibility;
use crate::signing::TokenSigner;
use crate::store::BridgeStore;
use crate::store::RepositoryRecord;

const CORRELATION_ID_HEADERS: [&str; 3] =
    ["x-epic-correlation-id", "x-correlation-id", "x-request-id"];
const DEFAULT_CORRELATION_ID: &str = "<no_correlation_id>";
const MAX_CORRELATION_ID_BYTES: usize = 128;
const CALLER_CONFLICT_LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Shared state across the HTTP token-exchange endpoints and gRPC registry/directory services.
pub struct BridgeRuntime {
    pub config: BridgeConfig,
    pub signer: TokenSigner,
    pub verifier: TokenVerifier,
    pub store: BridgeStore,
    pub(crate) discovery_bytes: Bytes,
    pub(crate) upstream_user_semaphore: tokio::sync::Semaphore,
}

impl BridgeRuntime {
    /// Constructs a `BridgeRuntime` from validated components.
    pub fn new(
        config: BridgeConfig,
        signer: TokenSigner,
        verifier: TokenVerifier,
        store: BridgeStore,
    ) -> Self {
        let discovery_bytes = serialize_openid_configuration(&config.issuer);
        let upstream_user_semaphore =
            tokio::sync::Semaphore::new(crate::grpc::MAX_FALLBACK_CONCURRENCY);
        Self {
            config,
            signer,
            verifier,
            store,
            discovery_bytes,
            upstream_user_semaphore,
        }
    }

    /// Records an authenticated login caller's directory profile, consulting `authentik`
    /// on the boxed cold path when a UUID caller presents a conflicting or post-confirmation username.
    #[lore_macro::test_pub]
    pub(crate) async fn record_caller_profile(&self, caller: &CallerClaims) {
        let has_api = self.verifier.has_authentik_api();
        let caller_username_refuted = if self.config.authentik.user_id_field
            == crate::config::UserIdField::Uuid
            && has_api
            && self.store.needs_live_uuid_username_check(
                &caller.identity,
                &caller.username,
                caller.token_iat,
            ) {
            Box::pin(self.resolve_uuid_username_conflict(&caller.identity, &caller.username)).await
        } else {
            false
        };
        if let Err(err) = self
            .store
            .upsert_caller_profile(
                &caller.identity,
                &caller.username,
                &caller.display_name,
                caller.token_iat,
                !has_api,
                caller_username_refuted,
            )
            .await
        {
            tracing::warn!(
                identity = %caller.identity,
                ?err,
                "failed to persist caller directory record"
            );
        }
    }

    /// Cold path refreshing the authoritative owner of `username` from `authentik` when a UUID
    /// caller presents a conflicting or post-confirmation username. Returns `true` when `authentik`
    /// confirms `identity` does not own `username`. Callers box this future so hot-path request
    /// futures stay small.
    #[lore_macro::test_pub]
    async fn resolve_uuid_username_conflict(&self, identity: &str, username: &str) -> bool {
        if !self
            .verifier
            .try_acquire_conflict_resolution_slot(identity, username)
        {
            return false;
        }
        let pre_owner = self.store.unconfirmed_username_owner(username);
        let lookup = tokio::time::timeout(CALLER_CONFLICT_LOOKUP_TIMEOUT, async {
            let _permit = self.upstream_user_semaphore.acquire().await.ok()?;
            match self
                .verifier
                .lookup_authentik_user_by_username_live(username)
                .await
            {
                Ok(remote) => Some(remote),
                Err(err) => {
                    tracing::warn!(
                        identity = %identity,
                        username = %username,
                        ?err,
                        "failed to refresh conflicting username owner from authentik"
                    );
                    None
                }
            }
        })
        .await;

        match lookup {
            Ok(Some(Some(remote))) => {
                let refuted_for_caller = self.store.canonical_lookup_key(&remote.id).as_deref()
                    != self.store.canonical_lookup_key(identity).as_deref();
                if let Err(err) = self.store.upsert_user(remote).await {
                    tracing::warn!(
                        identity = %identity,
                        username = %username,
                        ?err,
                        "failed to persist refreshed username owner"
                    );
                }
                refuted_for_caller
            }
            Ok(Some(None)) => {
                if let Some((owner_id, max_iat)) = pre_owner
                    && let Err(err) = self
                        .store
                        .clear_unconfirmed_username(username, &owner_id, max_iat)
                        .await
                {
                    tracing::warn!(
                        identity = %identity,
                        username = %username,
                        ?err,
                        "failed to clear unconfirmed conflicting username"
                    );
                }
                true
            }
            Ok(None) => false,
            Err(_elapsed) => {
                tracing::warn!(
                    identity = %identity,
                    username = %username,
                    "timed out refreshing conflicting username owner from authentik"
                );
                false
            }
        }
    }

    /// Resolves the stored and static visibility of `repo` without network I/O.
    pub fn effective_visibility(&self, repo: &RepositoryRecord) -> ProjectVisibility {
        let stored = self.store.project_visibility(&repo.project);
        let configured = self
            .config
            .projects
            .get(&repo.project)
            .map(|cfg| cfg.visibility);
        repo.visibility
            .merge(stored.unwrap_or(ProjectVisibility::Internal))
            .merge(configured.unwrap_or(ProjectVisibility::Internal))
    }

    /// Resolves the effective visibility of `repo` for `caller`, consulting the cached
    /// `authentik` group directory when `caller`'s access depends on live project visibility.
    pub async fn resolve_repo_visibility(
        &self,
        caller: &CallerClaims,
        repo: &RepositoryRecord,
    ) -> Result<ProjectVisibility, AuthentikDirectoryError> {
        let claim_vis = caller
            .projects
            .get(&repo.project)
            .map_or(ProjectVisibility::Internal, |grant| grant.visibility);
        let base = self.effective_visibility(repo).merge(claim_vis);
        if base == ProjectVisibility::Restricted
            || !caller_depends_on_project_visibility(caller, &repo.project)
            || !self.verifier.has_authentik_api()
        {
            return Ok(base);
        }
        let live = self.verifier.refresh_group_visibilities().await?;
        Ok(base.merge(resolve_configured_or_live_visibility(
            &repo.project,
            &self.config.projects,
            live.as_deref(),
        )))
    }

    /// Resolves the effective visibility of `repo` for a gRPC `VerifiedCaller`.
    pub async fn resolve_verified_caller_repo_visibility(
        &self,
        caller: &VerifiedCaller,
        repo: &RepositoryRecord,
    ) -> Result<ProjectVisibility, AuthentikDirectoryError> {
        match caller {
            VerifiedCaller::Login(login) => self.resolve_repo_visibility(login, repo).await,
            VerifiedCaller::Exchanged(_) => Ok(self.effective_visibility(repo)),
        }
    }
}

/// Extracts a bounded, control-character-free correlation ID from HTTP headers.
pub(crate) fn correlation_id_from_headers(headers: &HeaderMap) -> &str {
    for name in CORRELATION_ID_HEADERS {
        if let Some(raw) = headers.get(name).and_then(|v| v.to_str().ok())
            && is_clean_correlation_id(raw)
        {
            return raw;
        }
    }
    DEFAULT_CORRELATION_ID
}

/// Extracts a bounded, control-character-free correlation ID from gRPC metadata.
pub(crate) fn correlation_id_from_metadata(metadata: &MetadataMap) -> &str {
    correlation_id_from_headers(metadata.as_ref())
}

fn is_clean_correlation_id(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= MAX_CORRELATION_ID_BYTES
        && !raw.bytes().any(|b| b.is_ascii_control())
}

/// Builds the public `Router` serving HTTP OIDC endpoints and `UserService` without `RepositoryRegistryService`.
pub fn build_public_router(runtime: Arc<BridgeRuntime>) -> Router {
    let user_router = GrpcBridgeService::new(runtime.clone()).into_user_axum_router();
    build_http_router(runtime).merge(user_router)
}

/// Builds the combined HTTP + gRPC `Router` serving all endpoints on one listener.
pub fn build_combined_router(runtime: Arc<BridgeRuntime>) -> Router {
    let grpc_router = GrpcBridgeService::new(runtime.clone()).into_axum_router();
    build_http_router(runtime).merge(grpc_router)
}

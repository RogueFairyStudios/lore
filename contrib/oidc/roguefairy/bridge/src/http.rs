// SPDX-FileCopyrightText: 2026 Rogue Fairy Studios
// SPDX-License-Identifier: MIT

use std::borrow::Cow;
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::DefaultBodyLimit;
use axum::extract::FromRequest;
use axum::extract::Request;
use axum::extract::State;
use axum::http::HeaderValue;
use axum::http::StatusCode;
use axum::http::header;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::routing::get;
use axum::routing::post;
use lore_base::types::Context;
use lore_base::types::RepositoryId;
use serde::Serialize;
use tracing::Instrument as _;
use tracing::debug;
use tracing::info;
use tracing::warn;

use crate::BridgeRuntime;
use crate::correlation_id_from_headers;
use crate::error::AuthVerifyError;
use crate::jwks::AuthentikDirectoryError;
use crate::policy::BorrowedExchangedTokenClaims;
use crate::policy::BorrowedResourceGrantClaim;
use crate::policy::granted_action_set_on_project;
use crate::policy::render_resource_id;

pub const MAX_TOKEN_BODY_BYTES: usize = 64 * 1024;
const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
const TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
const HEALTH_OK_BYTES: Bytes = Bytes::from_static(br#"{"status":"ok"}"#);

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<&'a str>,
}

#[derive(Serialize)]
struct OpenIdConfigurationResponse<'a> {
    issuer: &'a str,
    token_endpoint: String,
    jwks_uri: String,
    grant_types_supported: [&'static str; 1],
    token_endpoint_auth_methods_supported: [&'static str; 1],
}

#[derive(Serialize)]
struct TokenExchangeResponse<'a> {
    access_token: &'a str,
    issued_token_type: &'static str,
    token_type: &'static str,
    expires_in: u64,
}

/// Pre-serializes the static OIDC discovery JSON payload for `issuer`.
pub(crate) fn serialize_openid_configuration(issuer: &str) -> Bytes {
    let doc = OpenIdConfigurationResponse {
        issuer,
        token_endpoint: format!("{issuer}/token"),
        jwks_uri: format!("{issuer}/jwks"),
        grant_types_supported: [GRANT_TYPE_TOKEN_EXCHANGE],
        token_endpoint_auth_methods_supported: ["none"],
    };
    Bytes::from(serde_json::to_vec(&doc).unwrap_or_default())
}

/// Builds the Axum HTTP router serving OIDC discovery, JWKS, health check, and RFC 8693 token exchange.
pub fn build_http_router(runtime: Arc<BridgeRuntime>) -> Router {
    let token_route = Router::new()
        .route("/token", post(token_exchange_handler))
        .layer(DefaultBodyLimit::max(MAX_TOKEN_BODY_BYTES));

    Router::new()
        .route("/health_check", get(health_check_handler))
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration_handler),
        )
        .route("/jwks", get(jwks_handler))
        .merge(token_route)
        .with_state(runtime)
}

#[allow(clippy::unused_async)]
async fn health_check_handler() -> Response {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        HEALTH_OK_BYTES,
    )
        .into_response()
}

#[allow(clippy::unused_async)]
async fn openid_configuration_handler(State(runtime): State<Arc<BridgeRuntime>>) -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        runtime.discovery_bytes.clone(),
    )
        .into_response()
}

#[allow(clippy::unused_async)]
async fn jwks_handler(State(runtime): State<Arc<BridgeRuntime>>) -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=300"),
            ),
        ],
        runtime.signer.jwks_bytes(),
    )
        .into_response()
}

async fn token_exchange_handler(
    State(runtime): State<Arc<BridgeRuntime>>,
    request: Request,
) -> Response {
    let span = tracing::info_span!(
        "token_exchange",
        correlation_id = correlation_id_from_headers(request.headers()),
    );
    token_exchange_inner(runtime, request)
        .instrument(span)
        .await
}

async fn token_exchange_inner(runtime: Arc<BridgeRuntime>, request: Request) -> Response {
    let body = match Bytes::from_request(request, &()).await {
        Ok(bytes) => bytes,
        Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return oauth_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request",
                Some("request body exceeds maximum size"),
            );
        }
        Err(_) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("unreadable request body"),
            );
        }
    };

    let mut grant_type: Option<Cow<'_, str>> = None;
    let mut subject_token: Option<Cow<'_, str>> = None;
    let mut subject_token_type: Option<Cow<'_, str>> = None;
    let mut requested_token_type: Option<Cow<'_, str>> = None;
    let mut scope: Option<Cow<'_, str>> = None;
    let mut audience: Option<Cow<'_, str>> = None;
    let mut resource: Option<Cow<'_, str>> = None;
    let mut duplicate_resource = false;

    for (key, val) in url::form_urlencoded::parse(&body) {
        let target = match key.as_ref() {
            "grant_type" => &mut grant_type,
            "subject_token" => &mut subject_token,
            "subject_token_type" => &mut subject_token_type,
            "requested_token_type" => &mut requested_token_type,
            "scope" => &mut scope,
            "audience" => &mut audience,
            "resource" => {
                if resource.is_some() {
                    duplicate_resource = true;
                } else {
                    resource = Some(val);
                }
                continue;
            }
            _ => continue,
        };
        if target.is_some() {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("duplicate form parameter"),
            );
        }
        *target = Some(val);
    }

    if grant_type.as_deref() != Some(GRANT_TYPE_TOKEN_EXCHANGE) {
        return oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type", None);
    }
    if subject_token_type.as_deref() != Some(TOKEN_TYPE_ACCESS_TOKEN) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("subject_token_type must be access_token"),
        );
    }
    if let Some(requested) = requested_token_type.as_deref()
        && requested != TOKEN_TYPE_ACCESS_TOKEN
        && requested != TOKEN_TYPE_JWT
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("unsupported requested_token_type"),
        );
    }
    if let Some(raw_scope) = scope.as_deref()
        && !raw_scope.trim().is_empty()
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            Some("scope narrowing is not supported"),
        );
    }
    if let Some(raw_audience) = audience.as_deref()
        && raw_audience != runtime.config.audience
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            Some("requested audience is not accepted"),
        );
    }

    let Some(raw_subject_token) = subject_token.as_deref().filter(|tok| !tok.is_empty()) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("missing subject_token"),
        );
    };

    let caller = match runtime.verifier.verify_login_token(raw_subject_token).await {
        Ok(claims) => claims,
        Err(AuthVerifyError::ProviderUnavailable { issuer }) => {
            warn!(%issuer, "login issuer JWKS unavailable during token exchange");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                Some("identity provider keys unavailable"),
            );
        }
        Err(_) => {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", None);
        }
    };

    let Some(single_resource) = resource.filter(|_| !duplicate_resource) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            Some("expected a single repository resource"),
        );
    };

    let Some(repository_id) =
        parse_partition_resource(single_resource.as_ref(), &runtime.config.resource_prefix)
    else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            Some("malformed partition resource"),
        );
    };

    let Some(repo) = runtime.store.get_repository(repository_id) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            Some("repository is not registered"),
        );
    };

    let effective_visibility = match runtime.resolve_repo_visibility(&caller, &repo).await {
        Ok(vis) => vis,
        Err(AuthentikDirectoryError::Unavailable) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                Some("authentik group directory unavailable"),
            );
        }
    };
    let actions = granted_action_set_on_project(&caller, &repo.project, effective_visibility);
    if actions.is_empty() {
        info!(
            identity = %caller.identity,
            repository = %repository_id,
            project = %repo.project,
            "refused token exchange: caller holds no permissions on project"
        );
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            Some("no grant on the repository"),
        );
    }

    let now = unix_timestamp_secs();
    let exp = caller
        .exp
        .min(now.saturating_add(runtime.config.token_lifetime_seconds));
    if exp <= now {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", None);
    }

    runtime.record_caller_profile(&caller).await;

    let resource_id = render_resource_id(&runtime.config.resource_id_template, repository_id);
    let mut perm_buf = [""; 8];
    let permissions = actions.write_static_strs(&mut perm_buf);
    let claims = BorrowedExchangedTokenClaims {
        iss: &runtime.config.issuer,
        sub: &caller.sub,
        identity: &caller.identity,
        aud: [&runtime.config.audience],
        root_domains: &runtime.config.root_domains,
        iat: now,
        exp,
        preferred_username: &caller.username,
        name: &caller.display_name,
        is_service_account: caller.is_service_account,
        resources: [BorrowedResourceGrantClaim {
            resource_id: &resource_id,
            permission: permissions,
        }],
    };

    let token = match runtime.signer.sign_access_token(&claims) {
        Ok(signed) => signed,
        Err(err) => {
            warn!(?err, "failed to sign exchanged access token");
            return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", None);
        }
    };

    debug!(
        identity = %caller.identity,
        repository = %repository_id,
        project = %repo.project,
        "issued partition access token"
    );

    no_store_json(
        StatusCode::OK,
        &TokenExchangeResponse {
            access_token: &token,
            issued_token_type: TOKEN_TYPE_ACCESS_TOKEN,
            token_type: "Bearer",
            expires_in: exp.saturating_sub(now),
        },
    )
}

fn parse_partition_resource(resource: &str, prefix: &str) -> Option<RepositoryId> {
    let raw_id = resource.strip_prefix(prefix)?;
    if raw_id.len() != 32
        || !raw_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let ctx = Context::from_str(raw_id).ok()?;
    (!ctx.is_zero()).then(|| RepositoryId::from(ctx))
}

fn oauth_error(status: StatusCode, error: &str, description: Option<&str>) -> Response {
    no_store_json(
        status,
        &ErrorBody {
            error,
            error_description: description,
        },
    )
}

fn no_store_json<T: Serialize>(status: StatusCode, payload: &T) -> Response {
    let mut response = (status, Json(payload)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Returns the current Unix timestamp in whole seconds.
pub(crate) fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

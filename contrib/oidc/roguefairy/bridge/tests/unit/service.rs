// SPDX-FileCopyrightText: 2026 Rogue Fairy Studios
// SPDX-License-Identifier: MIT

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use axum::Json;
use axum::Router;
use axum::extract::Query as AxumQuery;
use axum::extract::State;
use axum::response::IntoResponse as _;
use axum::routing::get;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::Algorithm;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::Header;
use jsonwebtoken::Validation;
use jsonwebtoken::decode;
use lore_base::lore_spawn;
use lore_base::types::Context;
use lore_base::types::RepositoryId;
use lore_proto::lore::user::v1::RepositoryListRequest;
use lore_proto::lore::user::v1::RepositoryRegisterRequest;
use lore_proto::lore::user::v1::RepositoryUnregisterRequest;
use lore_proto::lore::user::v1::UserFindRequest;
use lore_proto::lore::user::v1::UserGetRequest;
use lore_proto::lore::user::v1::repository_registry_service_client::RepositoryRegistryServiceClient;
use lore_proto::lore::user::v1::user_find_request::Query as FindQuery;
use lore_proto::lore::user::v1::user_service_client::UserServiceClient;
use rfs_lore_bridge::BridgeRuntime;
use rfs_lore_bridge::build_combined_router;
use rfs_lore_bridge::build_public_router;
use rfs_lore_bridge::config::AuthentikApiConfig;
use rfs_lore_bridge::config::BridgeConfig;
use rfs_lore_bridge::config::UserIdField;
use rfs_lore_bridge::grpc::GrpcBridgeService;
use rfs_lore_bridge::http::MAX_TOKEN_BODY_BYTES;
use rfs_lore_bridge::jwks::TokenVerifier;
use rfs_lore_bridge::policy::ExchangedTokenClaims;
use rfs_lore_bridge::signing::TokenSigner;
use rfs_lore_bridge::store::BridgeStore;
use ring::rand::SystemRandom;
use ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
use ring::signature::EcdsaKeyPair;
use ring::signature::KeyPair as _;
use serde_json::json;
use tokio::net::TcpListener;
use tokio_stream::StreamExt as _;
use tokio_util::task::AbortOnDropHandle;
use tonic::Code;
use tonic::Request;
use tonic::metadata::MetadataValue;

type JwksParkSlot = Arc<
    parking_lot::Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    >,
>;

struct MockAuthentik {
    base_url: String,
    cli_issuer: String,
    ci_issuer: String,
    kid: String,
    encoding_key: EncodingKey,
    v2_kid: String,
    v2_encoding_key: EncodingKey,
    cli_discovery_hits: Arc<AtomicUsize>,
    user_api_hits: Arc<AtomicUsize>,
    group_api_hits: Arc<AtomicUsize>,
    fail_users_503: Arc<std::sync::atomic::AtomicBool>,
    fail_groups_503: Arc<std::sync::atomic::AtomicBool>,
    fail_jwks_503: Arc<std::sync::atomic::AtomicBool>,
    hide_secretproto_group: Arc<std::sync::atomic::AtomicBool>,
    tighten_promotable_to_restricted: Arc<std::sync::atomic::AtomicBool>,
    alternate_jwks_uri: Arc<std::sync::atomic::AtomicBool>,
    jwks_park: JwksParkSlot,
    _server_task: AbortOnDropHandle<()>,
}

impl MockAuthentik {
    async fn spawn() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("generate mock authentik key");
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .expect("parse mock authentik key");
        let pub_bytes = pair.public_key().as_ref();
        let x = URL_SAFE_NO_PAD.encode(&pub_bytes[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&pub_bytes[33..65]);
        let kid = "authentik-test-kid".to_owned();
        let encoding_key = EncodingKey::from_ec_der(pkcs8.as_ref());

        let v2_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("generate mock authentik v2 key");
        let v2_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, v2_pkcs8.as_ref(), &rng)
                .expect("parse mock authentik v2 key");
        let v2_pub_bytes = v2_pair.public_key().as_ref();
        let v2_x = URL_SAFE_NO_PAD.encode(&v2_pub_bytes[1..33]);
        let v2_y = URL_SAFE_NO_PAD.encode(&v2_pub_bytes[33..65]);
        let v2_kid = "authentik-rotated-v2-kid".to_owned();
        let v2_encoding_key = EncodingKey::from_ec_der(v2_pkcs8.as_ref());

        let listener = bind_test_listener().await;
        let addr = listener.local_addr().expect("mock authentik addr");
        let base_url = format!("http://{addr}");
        let cli_issuer = format!("{base_url}/application/o/rfs-lore-cli/");
        let ci_issuer = format!("{base_url}/application/o/rfs-lore-ci/");

        #[derive(Clone)]
        struct MockIdpState {
            base_url: String,
            cli_issuer: String,
            ci_issuer: String,
            jwks: serde_json::Value,
            v2_jwks: serde_json::Value,
            cli_discovery_hits: Arc<AtomicUsize>,
            user_api_hits: Arc<AtomicUsize>,
            group_api_hits: Arc<AtomicUsize>,
            fail_users_503: Arc<std::sync::atomic::AtomicBool>,
            fail_groups_503: Arc<std::sync::atomic::AtomicBool>,
            fail_jwks_503: Arc<std::sync::atomic::AtomicBool>,
            hide_secretproto_group: Arc<std::sync::atomic::AtomicBool>,
            tighten_promotable_to_restricted: Arc<std::sync::atomic::AtomicBool>,
            alternate_jwks_uri: Arc<std::sync::atomic::AtomicBool>,
            jwks_park: JwksParkSlot,
        }

        let cli_discovery_hits = Arc::new(AtomicUsize::new(0));
        let user_api_hits = Arc::new(AtomicUsize::new(0));
        let group_api_hits = Arc::new(AtomicUsize::new(0));
        let fail_users_503 = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fail_groups_503 = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fail_jwks_503 = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hide_secretproto_group = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let tighten_promotable_to_restricted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let alternate_jwks_uri = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let jwks_park: JwksParkSlot = Arc::new(parking_lot::Mutex::new(None));
        let state = MockIdpState {
            base_url: base_url.clone(),
            cli_issuer: cli_issuer.clone(),
            ci_issuer: ci_issuer.clone(),
            jwks: json!({
                "keys": [{
                    "kty": "EC",
                    "crv": "P-256",
                    "alg": "ES256",
                    "use": "sig",
                    "kid": kid,
                    "x": x,
                    "y": y,
                }]
            }),
            v2_jwks: json!({
                "keys": [{
                    "kty": "EC",
                    "crv": "P-256",
                    "alg": "ES256",
                    "use": "sig",
                    "kid": v2_kid,
                    "x": v2_x,
                    "y": v2_y,
                }]
            }),
            cli_discovery_hits: cli_discovery_hits.clone(),
            user_api_hits: user_api_hits.clone(),
            group_api_hits: group_api_hits.clone(),
            fail_users_503: fail_users_503.clone(),
            fail_groups_503: fail_groups_503.clone(),
            fail_jwks_503: fail_jwks_503.clone(),
            hide_secretproto_group: hide_secretproto_group.clone(),
            tighten_promotable_to_restricted: tighten_promotable_to_restricted.clone(),
            alternate_jwks_uri: alternate_jwks_uri.clone(),
            jwks_park: jwks_park.clone(),
        };

        let app = Router::new()
            .route(
                "/application/o/rfs-lore-cli/.well-known/openid-configuration",
                get(|State(st): State<MockIdpState>| async move {
                    st.cli_discovery_hits.fetch_add(1, Ordering::SeqCst);
                    let suffix = if st.alternate_jwks_uri.load(Ordering::SeqCst) {
                        "jwks-v2/"
                    } else {
                        "jwks/"
                    };
                    Json(json!({
                        "issuer": st.cli_issuer,
                        "jwks_uri": format!("{}/application/o/rfs-lore-cli/{suffix}", st.base_url),
                    }))
                }),
            )
            .route(
                "/application/o/rfs-lore-ci/.well-known/openid-configuration",
                get(|State(st): State<MockIdpState>| async move {
                    Json(json!({
                        "issuer": st.ci_issuer,
                        "jwks_uri": format!("{}/application/o/rfs-lore-cli/jwks/", st.base_url),
                    }))
                }),
            )
            .route(
                "/application/o/rfs-lore-cli/jwks/",
                get(|State(st): State<MockIdpState>| async move {
                    let parked = st.jwks_park.lock().take();
                    if let Some((entered_tx, release_rx)) = parked {
                        let _ = entered_tx.send(());
                        let _ = release_rx.await;
                    }
                    if st.fail_jwks_503.load(Ordering::SeqCst) {
                        return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
                    }
                    Json(st.jwks).into_response()
                }),
            )
            .route(
                "/application/o/rfs-lore-cli/jwks-v2/",
                get(|State(st): State<MockIdpState>| async move {
                    if st.fail_jwks_503.load(Ordering::SeqCst) {
                        return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
                    }
                    Json(st.v2_jwks).into_response()
                }),
            )
            .route(
                "/api/v3/core/users/",
                get(
                    |State(st): State<MockIdpState>,
                     AxumQuery(params): AxumQuery<HashMap<String, String>>| async move {
                        st.user_api_hits.fetch_add(1, Ordering::SeqCst);
                        if st.fail_users_503.load(Ordering::SeqCst)
                            || params.get("username").map(String::as_str)
                                == Some("trigger_503_user")
                        {
                            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
                        }
                        if params.values().any(|v| v.len() > 1024) {
                            return axum::http::StatusCode::URI_TOO_LONG.into_response();
                        }
                        if params
                            .values()
                            .any(|v| v.bytes().any(|b| b.is_ascii_control()))
                        {
                            return axum::http::StatusCode::BAD_REQUEST.into_response();
                        }
                        if let Some(raw_uuid) = params.get("uuid")
                            && !is_test_syntactic_uuid(raw_uuid)
                        {
                            return (
                                axum::http::StatusCode::BAD_REQUEST,
                                Json(json!({ "uuid": ["Enter a valid UUID."] })),
                            )
                                .into_response();
                        }
                        if params.get("name").map(String::as_str)
                            == Some("Paginated Display Target")
                        {
                            let page = params.get("page").map_or("1", String::as_str);
                            if page == "1" {
                                return Json(json!({
                                    "pagination": { "next": 2 },
                                    "results": [{
                                        "username": "page1_decoy",
                                        "uuid": "00000000-0000-4000-8000-000000000201",
                                        "name": "Paginated Display Target Jr",
                                        "is_active": true
                                    }]
                                }))
                                .into_response();
                            }
                            return Json(json!({
                                "pagination": { "next": 0 },
                                "results": [{
                                    "username": "page2_paula",
                                    "uuid": "00000000-0000-4000-8000-000000000202",
                                    "name": "Paginated Display Target",
                                    "is_active": true
                                }]
                            }))
                            .into_response();
                        }
                        let is_active_only =
                            params.get("is_active").map(String::as_str) == Some("true");
                        if params.get("username").map(String::as_str) == Some("former_gina") {
                            if is_active_only {
                                return Json(json!({ "results": [] })).into_response();
                            }
                            return Json(json!({
                                "results": [{
                                    "username": "former_gina",
                                    "uuid": "00000000-0000-4000-8000-000000000077",
                                    "name": "Gina Former Employee",
                                    "is_active": false
                                }]
                            }))
                            .into_response();
                        }
                        if let Some(uname) = params.get("username").map(String::as_str)
                            && let Some(idx_str) = uname.strip_prefix("batch_author_")
                            && let Ok(idx) = idx_str.parse::<u32>()
                            && idx < 20
                        {
                            return Json(json!({
                                "results": [{
                                    "username": uname,
                                    "uuid": format!("00000000-0000-4000-8000-{idx:012}"),
                                    "name": format!("Batch Author {idx}"),
                                    "is_active": true
                                }]
                            }))
                            .into_response();
                        }
                        if params.get("username").map(String::as_str) == Some("uncached_frank")
                            || params.get("name").map(String::as_str)
                                == Some("Frank From Authentik")
                        {
                            Json(json!({
                                "results": [{
                                    "username": "uncached_frank",
                                    "uuid": "00000000-0000-4000-8000-000000000099",
                                    "name": "Frank From Authentik",
                                    "is_active": true
                                }]
                            }))
                            .into_response()
                        } else if params.get("username").map(String::as_str) == Some("uuid_helena")
                        {
                            Json(json!({
                                "results": [{
                                    "username": "uuid_helena",
                                    "uuid": "9a7b2c1d-0000-4000-8000-000000000001",
                                    "name": "Helena UUID",
                                    "is_active": true
                                }]
                            }))
                            .into_response()
                        } else if params.get("username").map(String::as_str) == Some("carla_uuid")
                            || params
                                .get("uuid")
                                .and_then(|u| normalize_test_uuid_hex(u))
                                .as_deref()
                                == Some("9a7b2c1d0000400080000000000000cc")
                        {
                            Json(json!({
                                "results": [{
                                    "username": "carla_uuid",
                                    "uuid": "9a7b2c1d-0000-4000-8000-0000000000cc",
                                    "name": "Carla UUID Creator",
                                    "is_active": true
                                }]
                            }))
                            .into_response()
                        } else if params
                            .get("uuid")
                            .and_then(|u| normalize_test_uuid_hex(u))
                            .as_deref()
                            == Some("9a7b2c1d000040008000000000000002")
                        {
                            Json(json!({
                                "results": [{
                                    "username": "uuid_igor",
                                    "uuid": "9a7b2c1d-0000-4000-8000-000000000002",
                                    "name": "Igor UUID",
                                    "is_active": true
                                }]
                            }))
                            .into_response()
                        } else {
                            Json(json!({ "results": [] })).into_response()
                        }
                    },
                ),
            )
            .route(
                "/api/v3/core/groups/",
                get(
                    |State(st): State<MockIdpState>,
                     AxumQuery(params): AxumQuery<HashMap<String, String>>| async move {
                        st.group_api_hits.fetch_add(1, Ordering::SeqCst);
                        if st.fail_groups_503.load(Ordering::SeqCst) {
                            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
                        }
                        if params.get("include_users").map(String::as_str) != Some("false") {
                            return axum::http::StatusCode::BAD_REQUEST.into_response();
                        }
                        let mut results = vec![
                            json!({
                                "name": "Rogue Fairy Studios - Confidential - Leads",
                                "attributes": {
                                    "lore_project": "confidential",
                                    "lore_visibility": "restricted",
                                    "lore_actions": ["read", "write", "admin"],
                                    "lore_can_create_repo": true
                                }
                            }),
                            json!({
                                "name": "Rogue Fairy Studios - GhostLore - Leads",
                                "attributes": {
                                    "lore_project": "ghostlore",
                                    "lore_visibility": "internal",
                                    "lore_actions": ["read", "write", "admin"],
                                    "lore_can_create_repo": true
                                }
                            }),
                        ];
                        if !st.hide_secretproto_group.load(Ordering::SeqCst) {
                            results.push(json!({
                                "name": "Rogue Fairy Studios - SecretProto - Leads",
                                "attributes": {
                                    "lore_project": "secretproto",
                                    "lore_visibility": "restricted",
                                    "lore_actions": ["read", "write", "admin"],
                                    "lore_can_create_repo": true
                                }
                            }));
                        }
                        let promotable_vis =
                            if st.tighten_promotable_to_restricted.load(Ordering::SeqCst) {
                                "restricted"
                            } else {
                                "internal"
                            };
                        results.push(json!({
                            "name": "Rogue Fairy Studios - Promotable - Leads",
                            "attributes": {
                                "lore_project": "promotable",
                                "lore_visibility": promotable_vis,
                                "lore_actions": ["read", "write", "admin"],
                                "lore_can_create_repo": true
                            }
                        }));
                        Json(json!({ "results": results })).into_response()
                    },
                ),
            )
            .with_state(state);

        let server_task = AbortOnDropHandle::new(lore_spawn!(serve_test_router(listener, app)));

        Self {
            base_url,
            cli_issuer,
            ci_issuer,
            kid,
            encoding_key,
            v2_kid,
            v2_encoding_key,
            cli_discovery_hits,
            user_api_hits,
            group_api_hits,
            fail_users_503,
            fail_groups_503,
            fail_jwks_503,
            hide_secretproto_group,
            tighten_promotable_to_restricted,
            alternate_jwks_uri,
            jwks_park,
            _server_task: server_task,
        }
    }

    fn park_next_jwks_fetch(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        *self.jwks_park.lock() = Some((entered_tx, release_rx));
        (entered_rx, release_tx)
    }

    fn mint_v2_login_token(&self, issuer: &str, claims: serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("JWT".to_owned());
        header.kid = Some(self.v2_kid.clone());
        let mut map = claims.as_object().expect("claims object").clone();
        map.entry("iss".to_owned()).or_insert_with(|| json!(issuer));
        map.entry("aud".to_owned())
            .or_insert_with(|| json!(["https://lore.roguefairy.net"]));
        map.entry("iat".to_owned())
            .or_insert_with(|| json!(1_700_000_000_u64));
        map.entry("exp".to_owned())
            .or_insert_with(|| json!(4_102_444_800_u64));
        jsonwebtoken::encode(&header, &map, &self.v2_encoding_key).expect("mint v2 login token")
    }

    fn mint_login_token(&self, issuer: &str, claims: serde_json::Value) -> String {
        self.mint_token_with_typ(issuer, Some("JWT"), claims)
    }

    fn mint_login_token_with_kid(
        &self,
        issuer: &str,
        kid: &str,
        claims: serde_json::Value,
    ) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("JWT".to_owned());
        header.kid = Some(kid.to_owned());
        let mut map = claims.as_object().expect("claims object").clone();
        map.entry("iss".to_owned()).or_insert_with(|| json!(issuer));
        map.entry("aud".to_owned())
            .or_insert_with(|| json!(["https://lore.roguefairy.net"]));
        map.entry("iat".to_owned())
            .or_insert_with(|| json!(1_700_000_000_u64));
        map.entry("exp".to_owned())
            .or_insert_with(|| json!(4_102_444_800_u64));
        jsonwebtoken::encode(&header, &map, &self.encoding_key).expect("mint login token")
    }

    fn mint_token_with_typ(
        &self,
        issuer: &str,
        typ: Option<&str>,
        claims: serde_json::Value,
    ) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.typ = typ.map(str::to_owned);
        header.kid = Some(self.kid.clone());
        let mut map = claims.as_object().expect("claims object").clone();
        map.entry("iss".to_owned()).or_insert_with(|| json!(issuer));
        map.entry("aud".to_owned())
            .or_insert_with(|| json!(["https://lore.roguefairy.net"]));
        map.entry("iat".to_owned())
            .or_insert_with(|| json!(1_700_000_000_u64));
        map.entry("exp".to_owned())
            .or_insert_with(|| json!(4_102_444_800_u64));
        jsonwebtoken::encode(&header, &map, &self.encoding_key).expect("mint login token")
    }
}

fn is_test_syntactic_uuid(raw: &str) -> bool {
    if raw.len() == 32 {
        return raw.bytes().all(|b| b.is_ascii_hexdigit());
    }
    if raw.len() != 36 {
        return false;
    }
    for (idx, b) in raw.bytes().enumerate() {
        if matches!(idx, 8 | 13 | 18 | 23) {
            if b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

async fn bind_test_listener() -> TcpListener {
    for attempt in 0..8_u8 {
        match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => return listener,
            Err(err) if attempt < 7 && err.raw_os_error() == Some(10055) => {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            Err(err) => panic!("bind test listener: {err:?}"),
        }
    }
    unreachable!("bind_test_listener loop returns or panics")
}

fn make_test_bridge_config(
    bind: String,
    issuer: String,
    login_issuers: Vec<String>,
    authentik_base_url: Option<String>,
    user_id_field: UserIdField,
) -> BridgeConfig {
    let config = BridgeConfig {
        bind,
        grpc_bind: None,
        issuer,
        provider_url: None,
        login_issuers,
        login_audiences: vec!["https://lore.roguefairy.net".to_owned()],
        audience: "https://lore.roguefairy.net".to_owned(),
        root_domains: vec![
            ".roguefairy.net".to_owned(),
            "127.0.0.1".to_owned(),
            "localhost".to_owned(),
        ],
        resource_prefix: "https://lore.roguefairy.net/partitions/".to_owned(),
        resource_id_template: "urc-{id}".to_owned(),
        token_lifetime_seconds: 300,
        state_path: None,
        user_state_path: None,
        signing_key_path: None,
        signing_key_b64: None,
        authentik: AuthentikApiConfig {
            base_url: authentik_base_url,
            api_token: Some("test-authentik-api-token".to_owned()),
            user_id_field,
        },
        policy: rfs_lore_bridge::config::PolicyConfig::default(),
        projects: BTreeMap::new(),
    };
    config.validate().expect("test config valid");
    config
}

struct RunningBridge {
    addr: SocketAddr,
    base_url: String,
    signer: TokenSigner,
    runtime: Arc<BridgeRuntime>,
    _server_task: AbortOnDropHandle<()>,
}

impl RunningBridge {
    async fn spawn(idp: &MockAuthentik) -> Self {
        Self::spawn_with_user_id_field(idp, UserIdField::Username).await
    }

    async fn spawn_with_user_id_field(idp: &MockAuthentik, user_id_field: UserIdField) -> Self {
        let listener = bind_test_listener().await;
        let addr = listener.local_addr().expect("bridge local addr");
        let base_url = format!("http://{addr}");

        let config = make_test_bridge_config(
            addr.to_string(),
            base_url.clone(),
            vec![idp.cli_issuer.clone(), idp.ci_issuer.clone()],
            Some(idp.base_url.clone()),
            user_id_field,
        );

        let (signer, _) = TokenSigner::load_or_generate(None, None).expect("ephemeral signer");
        let verifier = TokenVerifier::new(config.clone(), signer.clone()).expect("verifier");
        let store =
            BridgeStore::open_with_user_id_field(None, user_id_field).expect("in-memory store");
        let runtime = Arc::new(BridgeRuntime::new(config, signer.clone(), verifier, store));
        let app = build_combined_router(runtime.clone());

        let server_task = AbortOnDropHandle::new(lore_spawn!(serve_test_router(listener, app)));

        Self {
            addr,
            base_url,
            signer,
            runtime,
            _server_task: server_task,
        }
    }
}

async fn serve_test_router(listener: TcpListener, app: Router) {
    let _ = axum::serve(listener, app).await;
}

fn bearer_request<T>(payload: T, token: &str) -> Request<T> {
    let mut req = Request::new(payload);
    let header_val =
        MetadataValue::try_from(format!("Bearer {token}")).expect("valid bearer metadata");
    req.metadata_mut().insert("authorization", header_val);
    req
}

fn repo_id(hex_str: &str) -> RepositoryId {
    RepositoryId::from(Context::from_str(hex_str).expect("valid 32-hex id"))
}

#[tokio::test]
async fn end_to_end_project_registry_token_exchange_and_user_directory() {
    let idp = MockAuthentik::spawn().await;
    let bridge = RunningBridge::spawn(&idp).await;
    let http = reqwest::Client::new();

    let health: serde_json::Value = http
        .get(format!("{}/health_check", bridge.base_url))
        .send()
        .await
        .expect("health_check")
        .json()
        .await
        .expect("health json");
    assert_eq!(health["status"], "ok");

    let discovery: serde_json::Value = http
        .get(format!(
            "{}/.well-known/openid-configuration",
            bridge.base_url
        ))
        .send()
        .await
        .expect("discovery")
        .json()
        .await
        .expect("discovery json");
    assert_eq!(discovery["issuer"], bridge.base_url);
    assert_eq!(
        discovery["token_endpoint"],
        format!("{}/token", bridge.base_url)
    );

    let alice_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-alice",
            "identity": "alice",
            "preferred_username": "alice",
            "name": "Alice C-Level",
            "rfs_lore": {
                "is_c_level": true,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": true,
                "global_actions": ["read", "write", "owner", "admin", "migrate", "push-protected", "obliterate", "presign"],
                "projects": {}
            }
        }),
    );

    let carla_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-carla",
            "identity": "carla",
            "preferred_username": "carla",
            "name": "Carla Lead",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {
                    "ghostlore": {
                        "actions": ["read", "write", "admin", "presign"],
                        "can_create_repo": true,
                        "visibility": "internal"
                    },
                    "secretproto": {
                        "actions": ["read", "write", "admin"],
                        "can_create_repo": true,
                        "visibility": "restricted"
                    }
                }
            }
        }),
    );

    let bruno_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-bruno",
            "identity": "bruno",
            "preferred_username": "bruno",
            "name": "Bruno Dev",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {}
            }
        }),
    );

    let diego_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-diego",
            "identity": "diego",
            "preferred_username": "diego",
            "name": "Diego Partner",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": false,
                "is_partner": true,
                "can_create_any": false,
                "global_actions": [],
                "projects": {
                    "ghostlore": {
                        "actions": ["read"],
                        "can_create_repo": false,
                        "visibility": "internal"
                    }
                }
            }
        }),
    );

    let eva_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-eva",
            "identity": "eva",
            "preferred_username": "eva",
            "name": "Eva Partner",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": false,
                "is_partner": true,
                "can_create_any": false,
                "global_actions": [],
                "projects": {}
            }
        }),
    );

    let ci_token = idp.mint_login_token(
        &idp.ci_issuer,
        json!({
            "sub": "sub-ci",
            "identity": "ak-rfs-lore-ci-client_credentials",
            "preferred_username": "ak-rfs-lore-ci-client_credentials",
            "name": "Rogue Fairy Lore CI",
            "is_service_account": true,
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": false,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": ["read", "write", "push-protected"],
                "projects": {}
            }
        }),
    );

    let mut registry = RepositoryRegistryServiceClient::connect(format!("http://{}", bridge.addr))
        .await
        .expect("connect RepositoryRegistryService on multiplexed port");
    let mut users = UserServiceClient::connect(format!("http://{}", bridge.addr))
        .await
        .expect("connect UserService on multiplexed port");

    let ghostlore_id = repo_id("11111111111111111111111111111111");
    let secret_id = repo_id("22222222222222222222222222222222");

    let missing_ns = registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: ghostlore_id.into(),
                name: "standalone".to_owned(),
            },
            &alice_token,
        ))
        .await
        .expect_err("standalone name must fail");
    assert_eq!(missing_ns.code(), Code::InvalidArgument);
    assert!(
        missing_ns
            .message()
            .contains("Missing resource context in resourceName")
    );

    let bruno_create = registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: ghostlore_id.into(),
                name: "ghostlore/game".to_owned(),
            },
            &bruno_token,
        ))
        .await
        .expect_err("employee without lead attribute cannot create");
    assert_eq!(bruno_create.code(), Code::PermissionDenied);

    registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: ghostlore_id.into(),
                name: "ghostlore/game".to_owned(),
            },
            &carla_token,
        ))
        .await
        .expect("carla creates ghostlore/game");

    registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: secret_id.into(),
                name: "secretproto/engine".to_owned(),
            },
            &carla_token,
        ))
        .await
        .expect("carla creates secretproto/engine");

    let list_for = |client: &mut RepositoryRegistryServiceClient<_>, token: String| {
        let mut cloned = client.clone();
        async move {
            let mut stream = cloned
                .repository_list(bearer_request(RepositoryListRequest {}, &token))
                .await
                .expect("repository_list")
                .into_inner();
            let mut items = Vec::new();
            while let Some(msg) = stream.next().await {
                items.push(msg.expect("stream item"));
            }
            items
        }
    };

    let alice_list = list_for(&mut registry, alice_token.clone()).await;
    assert_eq!(alice_list.len(), 2);

    let bruno_list = list_for(&mut registry, bruno_token.clone()).await;
    assert_eq!(bruno_list.len(), 1);
    assert_eq!(bruno_list[0].id.as_ref(), ghostlore_id.as_ref());
    assert_eq!(bruno_list[0].permission, vec!["read", "write"]);

    let diego_list = list_for(&mut registry, diego_token.clone()).await;
    assert_eq!(diego_list.len(), 1);
    assert_eq!(diego_list[0].id.as_ref(), ghostlore_id.as_ref());
    assert_eq!(diego_list[0].permission, vec!["read"]);

    let eva_list = list_for(&mut registry, eva_token.clone()).await;
    assert!(eva_list.is_empty());

    let exchange = |subject_token: &str, id: RepositoryId| {
        let client = http.clone();
        let url = format!("{}/token", bridge.base_url);
        let tok = subject_token.to_owned();
        async move {
            client
                .post(url)
                .form(&[
                    (
                        "grant_type",
                        "urn:ietf:params:oauth:grant-type:token-exchange",
                    ),
                    ("subject_token", &tok),
                    (
                        "subject_token_type",
                        "urn:ietf:params:oauth:token-type:access_token",
                    ),
                    (
                        "resource",
                        &format!("https://lore.roguefairy.net/partitions/{id}"),
                    ),
                ])
                .send()
                .await
                .expect("POST /token")
        }
    };

    let bruno_resp = exchange(&bruno_token, ghostlore_id).await;
    assert_eq!(bruno_resp.status(), 200);
    let bruno_body: serde_json::Value = bruno_resp.json().await.expect("bruno exchange json");
    let bruno_at_jwt = bruno_body["access_token"]
        .as_str()
        .expect("access_token")
        .to_owned();

    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&["https://lore.roguefairy.net"]);
    validation.set_issuer(std::slice::from_ref(&bridge.base_url));
    let decoded_bruno =
        decode::<ExchangedTokenClaims>(&bruno_at_jwt, bridge.signer.decoding_key(), &validation)
            .expect("verify exchanged token against bridge key");
    assert_eq!(decoded_bruno.claims.identity, "bruno");
    assert_eq!(
        decoded_bruno.claims.resources[0].permission,
        vec!["read", "write"]
    );
    assert!(
        decoded_bruno
            .claims
            .root_domains
            .contains(&".roguefairy.net".to_owned())
    );

    let bruno_secret = exchange(&bruno_token, secret_id).await;
    assert_eq!(bruno_secret.status(), 400);
    let err_json: serde_json::Value = bruno_secret.json().await.expect("err json");
    assert_eq!(err_json["error"], "invalid_target");

    let diego_resp = exchange(&diego_token, ghostlore_id).await;
    assert_eq!(diego_resp.status(), 200);
    let diego_body: serde_json::Value = diego_resp.json().await.expect("diego json");
    let diego_at_jwt = diego_body["access_token"]
        .as_str()
        .expect("diego access_token")
        .to_owned();
    let decoded_diego =
        decode::<ExchangedTokenClaims>(&diego_at_jwt, bridge.signer.decoding_key(), &validation)
            .expect("verify diego token");
    assert_eq!(decoded_diego.claims.resources[0].permission, vec!["read"]);

    let eva_resp = exchange(&eva_token, ghostlore_id).await;
    assert_eq!(eva_resp.status(), 400);

    let ci_resp = exchange(&ci_token, ghostlore_id).await;
    assert_eq!(ci_resp.status(), 200);
    let ci_body: serde_json::Value = ci_resp.json().await.expect("ci json");
    let decoded_ci = decode::<ExchangedTokenClaims>(
        ci_body["access_token"].as_str().expect("ci tok"),
        bridge.signer.decoding_key(),
        &validation,
    )
    .expect("verify ci token");
    assert!(decoded_ci.claims.is_service_account);
    assert!(
        decoded_ci.claims.resources[0]
            .permission
            .contains(&"push-protected".to_owned())
    );

    let reexchange = exchange(&bruno_at_jwt, ghostlore_id).await;
    assert_eq!(reexchange.status(), 400);
    let reexchange_json: serde_json::Value = reexchange.json().await.expect("reexchange json");
    assert_eq!(reexchange_json["error"], "invalid_grant");

    let oversized = http
        .post(format!("{}/token", bridge.base_url))
        .body("x".repeat(MAX_TOKEN_BODY_BYTES + 1024))
        .send()
        .await
        .expect("oversized POST");
    assert_eq!(oversized.status(), 413);

    let got_users = users
        .user_get(bearer_request(
            UserGetRequest {
                partition: ghostlore_id.into(),
                id: vec!["carla".to_owned(), "uncached_frank".to_owned()],
            },
            &bruno_at_jwt,
        ))
        .await
        .expect("UserGet")
        .into_inner()
        .user;
    assert_eq!(got_users.len(), 2);

    let found_carla = users
        .user_find(bearer_request(
            UserFindRequest {
                partition: ghostlore_id.into(),
                query: Some(FindQuery::DisplayName("Carla Lead".to_owned())),
            },
            &bruno_at_jwt,
        ))
        .await
        .expect("UserFind")
        .into_inner()
        .user;
    assert_eq!(found_carla.len(), 1);
    assert_eq!(found_carla[0].id, "carla");

    let cross_partition = users
        .user_get(bearer_request(
            UserGetRequest {
                partition: secret_id.into(),
                id: vec!["carla".to_owned()],
            },
            &diego_at_jwt,
        ))
        .await
        .expect_err("cross-partition UserGet must fail");
    assert_eq!(cross_partition.code(), Code::PermissionDenied);

    let bruno_unreg = registry
        .repository_unregister(bearer_request(
            RepositoryUnregisterRequest {
                id: ghostlore_id.into(),
            },
            &bruno_at_jwt,
        ))
        .await
        .expect_err("bruno cannot unregister");
    assert_eq!(bruno_unreg.code(), Code::PermissionDenied);

    let carla_exchanged = exchange(&carla_token, ghostlore_id)
        .await
        .json::<serde_json::Value>()
        .await
        .expect("carla exchange")["access_token"]
        .as_str()
        .expect("carla access_token")
        .to_owned();

    registry
        .repository_unregister(bearer_request(
            RepositoryUnregisterRequest {
                id: ghostlore_id.into(),
            },
            &carla_exchanged,
        ))
        .await
        .expect("carla unregisters ghostlore/game with exchanged at+jwt");

    let after_delete = exchange(&bruno_token, ghostlore_id).await;
    assert_eq!(after_delete.status(), 400);
}

#[tokio::test]
async fn c_level_registration_resolves_restricted_project_and_refuses_unknown_project() {
    let idp = MockAuthentik::spawn().await;
    let bridge = RunningBridge::spawn(&idp).await;
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{}", bridge.addr))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect");
    let mut registry = RepositoryRegistryServiceClient::new(channel);

    let alice_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-alice",
            "identity": "alice",
            "preferred_username": "alice",
            "name": "Alice C-Level",
            "rfs_lore": {
                "is_c_level": true,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": true,
                "global_actions": ["read", "write", "owner", "admin", "migrate", "push-protected", "obliterate", "presign"],
                "projects": {}
            }
        }),
    );
    let bruno_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-bruno",
            "identity": "bruno",
            "preferred_username": "bruno",
            "name": "Bruno Dev",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {}
            }
        }),
    );

    let bad_slug_err = registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: repo_id("33333333333333333333333333333333").into(),
                name: "GhostLore/game".to_owned(),
            },
            &alice_token,
        ))
        .await
        .expect_err("uppercase project slug must fail");
    assert_eq!(bad_slug_err.code(), Code::InvalidArgument);
    assert!(
        bad_slug_err
            .message()
            .contains("Missing resource context in resourceName"),
        "loreserver add_outcome requires this protocol marker to surface InvalidArgument"
    );

    let unknown_id = repo_id("44444444444444444444444444444444");
    let unknown_err = registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: unknown_id.into(),
                name: "typo-unknown-project/game".to_owned(),
            },
            &alice_token,
        ))
        .await
        .expect_err("unknown project without authentik group or static config must be refused");
    assert_eq!(unknown_err.code(), Code::NotFound);

    // `confidential` exists in authentik `/api/v3/core/groups/` with `lore_visibility: restricted`.
    // When Alice (C-Level, `projects: {}`) registers `confidential/proto`, Bridge must learn
    // `restricted` so regular employee Bruno cannot see or exchange for it.
    let conf_id = repo_id("55555555555555555555555555555555");
    registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: conf_id.into(),
                name: "confidential/proto".to_owned(),
            },
            &alice_token,
        ))
        .await
        .expect("alice registers confidential/proto");

    let mut bruno_stream = registry
        .repository_list(bearer_request(RepositoryListRequest {}, &bruno_token))
        .await
        .expect("bruno list")
        .into_inner();
    assert!(
        bruno_stream.next().await.is_none(),
        "employee Bruno must not see restricted project registered by C-Level"
    );
}

#[tokio::test]
async fn security_and_consistency_edge_cases_hold() {
    let idp = MockAuthentik::spawn().await;
    let bridge = RunningBridge::spawn(&idp).await;
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{}", bridge.addr))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect");
    let mut registry = RepositoryRegistryServiceClient::new(channel.clone());
    let mut users = UserServiceClient::new(channel);
    let http = reqwest::Client::new();

    let carla_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-carla",
            "identity": "carla",
            "preferred_username": "carla",
            "name": "Carla Lead",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {
                    "ghostlore": {
                        "actions": ["read", "write", "admin"],
                        "can_create_repo": true,
                        "visibility": "internal"
                    }
                }
            }
        }),
    );
    let diego_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-diego",
            "identity": "diego",
            "preferred_username": "diego",
            "name": "Diego Partner",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": false,
                "is_partner": true,
                "can_create_any": false,
                "global_actions": [],
                "projects": {
                    "ghostlore": {
                        "actions": ["read"],
                        "can_create_repo": false,
                        "visibility": "internal"
                    }
                }
            }
        }),
    );

    let zero_err = registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: vec![0_u8; 16].into(),
                name: "ghostlore/zero".to_owned(),
            },
            &carla_token,
        ))
        .await
        .expect_err("all-zero repository id must fail");
    assert_eq!(zero_err.code(), Code::InvalidArgument);

    let ghost_id = repo_id("66666666666666666666666666666666");
    registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: ghost_id.into(),
                name: "ghostlore/main".to_owned(),
            },
            &carla_token,
        ))
        .await
        .expect("register ghostlore/main");

    for unpartitioned in [Vec::new(), vec![0_u8; 16]] {
        let err = users
            .user_get(bearer_request(
                UserGetRequest {
                    partition: unpartitioned.into(),
                    id: vec!["carla".to_owned()],
                },
                &diego_token,
            ))
            .await
            .expect_err("partner must be denied on unpartitioned UserGet");
        assert_eq!(err.code(), Code::PermissionDenied);
    }

    let null_identity_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-carla",
            "identity": null,
            "preferred_username": "carla"
        }),
    );
    let null_resp = http
        .post(format!("{}/token", bridge.base_url))
        .form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", null_identity_token.as_str()),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            (
                "resource",
                &format!("https://lore.roguefairy.net/partitions/{ghost_id}"),
            ),
        ])
        .send()
        .await
        .expect("POST /token with null identity");
    assert_eq!(null_resp.status(), 400);

    idp.user_api_hits.store(0, Ordering::SeqCst);
    let dedup_users = users
        .user_get(bearer_request(
            UserGetRequest {
                partition: ghost_id.into(),
                id: vec![
                    "uncached_frank".to_owned(),
                    "uncached_frank".to_owned(),
                    "uncached_frank".to_owned(),
                ],
            },
            &carla_token,
        ))
        .await
        .expect("UserGet dedup")
        .into_inner()
        .user;
    assert_eq!(dedup_users.len(), 1);
    assert_eq!(idp.user_api_hits.load(Ordering::SeqCst), 1);

    idp.user_api_hits.store(0, Ordering::SeqCst);
    for _ in 0..2 {
        let miss = users
            .user_get(bearer_request(
                UserGetRequest {
                    partition: ghost_id.into(),
                    id: vec!["no_such_user_in_authentik".to_owned()],
                },
                &carla_token,
            ))
            .await
            .expect("UserGet miss")
            .into_inner()
            .user;
        assert!(miss.is_empty());
    }
    assert_eq!(idp.user_api_hits.load(Ordering::SeqCst), 1);

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let short_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-carla",
            "identity": "carla",
            "exp": now_secs + 45,
            "rfs_lore": {
                "is_employee": true
            }
        }),
    );
    let clamped_body: serde_json::Value = http
        .post(format!("{}/token", bridge.base_url))
        .form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", short_token.as_str()),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            (
                "resource",
                &format!("https://lore.roguefairy.net/partitions/{ghost_id}"),
            ),
        ])
        .send()
        .await
        .expect("short exchange")
        .json()
        .await
        .expect("short exchange json");
    let clamped_ttl = clamped_body["expires_in"].as_u64().expect("expires_in");
    assert!(
        (1..=45).contains(&clamped_ttl),
        "expires_in ({clamped_ttl}) must be clamped to subject_token remaining lifetime"
    );

    let expired_subject = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-carla",
            "identity": "carla",
            "exp": 1_700_000_001_u64,
            "rfs_lore": {
                "is_employee": true
            }
        }),
    );
    let expired_resp = http
        .post(format!("{}/token", bridge.base_url))
        .form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", expired_subject.as_str()),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            (
                "resource",
                &format!("https://lore.roguefairy.net/partitions/{ghost_id}"),
            ),
        ])
        .send()
        .await
        .expect("expired exchange");
    assert_eq!(expired_resp.status(), 400);

    let exch_body: serde_json::Value = http
        .post(format!("{}/token", bridge.base_url))
        .form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", carla_token.as_str()),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            (
                "resource",
                &format!("https://lore.roguefairy.net/partitions/{ghost_id}"),
            ),
        ])
        .send()
        .await
        .expect("exchange carla")
        .json()
        .await
        .expect("exchange json");
    let carla_at_jwt = exch_body["access_token"].as_str().expect("tok").to_owned();

    registry
        .repository_unregister(bearer_request(
            RepositoryUnregisterRequest {
                id: ghost_id.into(),
            },
            &carla_at_jwt,
        ))
        .await
        .expect("unregister ghostlore/main");

    let mut stale_list = registry
        .repository_list(bearer_request(RepositoryListRequest {}, &carla_at_jwt))
        .await
        .expect("list with exchanged token after delete")
        .into_inner();
    assert!(
        stale_list.next().await.is_none(),
        "unregistered repository must not appear in RepositoryList for an unexpired at+jwt"
    );

    let stale_user_get = users
        .user_get(bearer_request(
            UserGetRequest {
                partition: ghost_id.into(),
                id: vec!["carla".to_owned()],
            },
            &carla_at_jwt,
        ))
        .await
        .expect_err("unregistered partition must deny UserGet even for unexpired at+jwt");
    assert_eq!(stale_user_get.code(), Code::PermissionDenied);
}

#[tokio::test]
async fn jwks_discovery_rejects_third_party_origin_under_provider_url_and_skips_refresh_on_expired_token()
 {
    let rogue_listener = bind_test_listener().await;
    let rogue_addr = rogue_listener.local_addr().expect("rogue addr");
    let rogue_url = format!("http://{rogue_addr}");

    let rng = SystemRandom::new();
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).expect("rogue key");
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
        .expect("parse rogue key");
    let pub_bytes = pair.public_key().as_ref();
    let x = URL_SAFE_NO_PAD.encode(&pub_bytes[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&pub_bytes[33..65]);
    let rogue_enc = EncodingKey::from_ec_der(pkcs8.as_ref());

    let rogue_jwks = json!({
        "keys": [
            {
                "kty": "oct",
                "alg": "HS256",
                "use": "sig",
                "kid": "symmetric-ignored",
                "k": "c2VjcmV0"
            },
            {
                "kty": "EC",
                "crv": "P-256",
                "alg": "ES256",
                "use": "sig",
                "kid": "rogue-kid",
                "x": x,
                "y": y
            }
        ]
    });
    let rogue_jwks_clone = rogue_jwks.clone();
    let rogue_url_clone = rogue_url.clone();
    let rogue_app = Router::new()
        .route(
            "/application/o/rfs-lore-cli/.well-known/openid-configuration",
            get(move || {
                let base = rogue_url_clone.clone();
                async move {
                    Json(json!({
                        "issuer": "http://evil.example:9999/application/o/rfs-lore-cli/",
                        "jwks_uri": format!("{base}/jwks")
                    }))
                }
            }),
        )
        .route(
            "/jwks",
            get(move || {
                let jwks = rogue_jwks_clone.clone();
                async move { Json(jwks) }
            }),
        );
    let _rogue_task =
        AbortOnDropHandle::new(lore_spawn!(serve_test_router(rogue_listener, rogue_app)));

    let expected_issuer = "http://localhost:9000/application/o/rfs-lore-cli/".to_owned();
    let cfg = BridgeConfig {
        bind: "127.0.0.1:0".to_owned(),
        grpc_bind: None,
        issuer: "http://127.0.0.1:8190".to_owned(),
        provider_url: Some(rogue_url),
        login_issuers: vec![expected_issuer.clone()],
        login_audiences: vec!["https://lore.roguefairy.net".to_owned()],
        audience: "https://lore.roguefairy.net".to_owned(),
        root_domains: vec![
            ".roguefairy.net".to_owned(),
            "127.0.0.1".to_owned(),
            "localhost".to_owned(),
        ],
        resource_prefix: "https://lore.roguefairy.net/partitions/".to_owned(),
        resource_id_template: "urc-{id}".to_owned(),
        token_lifetime_seconds: 300,
        state_path: None,
        user_state_path: None,
        signing_key_path: None,
        signing_key_b64: None,
        authentik: AuthentikApiConfig::default(),
        policy: rfs_lore_bridge::config::PolicyConfig::default(),
        projects: BTreeMap::new(),
    };
    let (signer, _) = TokenSigner::load_or_generate(None, None).expect("signer");
    let verifier = TokenVerifier::new(cfg, signer).expect("verifier");

    let mut hdr = Header::new(Algorithm::ES256);
    hdr.kid = Some("rogue-kid".to_owned());
    let forged = jsonwebtoken::encode(
        &hdr,
        &json!({
            "iss": expected_issuer,
            "sub": "alice",
            "identity": "alice",
            "aud": ["https://lore.roguefairy.net"],
            "iat": 1_700_000_000_u64,
            "exp": 4_102_444_800_u64
        }),
        &rogue_enc,
    )
    .expect("mint forged");

    assert!(
        matches!(
            verifier.verify_login_token(&forged).await,
            Err(rfs_lore_bridge::error::AuthVerifyError::ProviderUnavailable { .. })
        ),
        "discovery document naming a third-party origin must be rejected even with provider_url"
    );

    let rot_listener = bind_test_listener().await;
    let rot_addr = rot_listener.local_addr().expect("rot addr");
    let rot_base = format!("http://{rot_addr}");
    let rot_issuer = format!("{rot_base}/application/o/rfs-lore-cli/");

    let pkcs8_b =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).expect("key b");
    let pair_b = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_b.as_ref(), &rng)
        .expect("parse key b");
    let pub_b = pair_b.public_key().as_ref();
    let xb = URL_SAFE_NO_PAD.encode(&pub_b[1..33]);
    let yb = URL_SAFE_NO_PAD.encode(&pub_b[33..65]);
    let enc_b = EncodingKey::from_ec_der(pkcs8_b.as_ref());

    let jwks_hits = Arc::new(AtomicUsize::new(0));
    let serve_503 = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let active_jwks = Arc::new(parking_lot::RwLock::new(rogue_jwks.clone()));

    let hits_route = jwks_hits.clone();
    let fail_route = serve_503.clone();
    let jwks_route = active_jwks.clone();
    let issuer_for_disc = rot_issuer.clone();
    let base_for_disc = rot_base.clone();
    let rot_app = Router::new()
        .route(
            "/application/o/rfs-lore-cli/.well-known/openid-configuration",
            get(move || {
                let iss = issuer_for_disc.clone();
                let base = base_for_disc.clone();
                async move {
                    Json(json!({
                        "issuer": iss,
                        "jwks_uri": format!("{base}/jwks")
                    }))
                }
            }),
        )
        .route(
            "/jwks",
            get(move || {
                let hits = hits_route.clone();
                let fail = fail_route.clone();
                let current = jwks_route.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    if fail.load(Ordering::SeqCst) {
                        axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response()
                    } else {
                        Json(current.read().clone()).into_response()
                    }
                }
            }),
        );
    let _rot_task = AbortOnDropHandle::new(lore_spawn!(serve_test_router(rot_listener, rot_app)));

    let rot_cfg = BridgeConfig {
        bind: "127.0.0.1:0".to_owned(),
        grpc_bind: None,
        issuer: "http://127.0.0.1:8190".to_owned(),
        provider_url: None,
        login_issuers: vec![rot_issuer.clone()],
        login_audiences: vec!["https://lore.roguefairy.net".to_owned()],
        audience: "https://lore.roguefairy.net".to_owned(),
        root_domains: vec![".roguefairy.net".to_owned(), "127.0.0.1".to_owned()],
        resource_prefix: "https://lore.roguefairy.net/partitions/".to_owned(),
        resource_id_template: "urc-{id}".to_owned(),
        token_lifetime_seconds: 300,
        state_path: None,
        user_state_path: None,
        signing_key_path: None,
        signing_key_b64: None,
        authentik: AuthentikApiConfig::default(),
        policy: rfs_lore_bridge::config::PolicyConfig::default(),
        projects: BTreeMap::new(),
    };
    let (rot_signer, _) = TokenSigner::load_or_generate(None, None).expect("rot signer");
    let rot_verifier = TokenVerifier::new(rot_cfg, rot_signer).expect("rot verifier");

    let valid_key_a = jsonwebtoken::encode(
        &hdr,
        &json!({
            "iss": rot_issuer,
            "sub": "alice",
            "identity": "alice",
            "aud": ["https://lore.roguefairy.net"],
            "iat": 1_700_000_000_u64,
            "exp": 4_102_444_800_u64
        }),
        &rogue_enc,
    )
    .expect("valid key a");

    assert!(matches!(
        rot_verifier.verify_login_token(&valid_key_a).await,
        Err(rfs_lore_bridge::error::AuthVerifyError::ProviderUnavailable { .. })
    ));
    assert_eq!(jwks_hits.load(Ordering::SeqCst), 1);

    serve_503.store(false, Ordering::SeqCst);
    rot_verifier.clear_refresh_backoff();
    let claims_a = rot_verifier
        .verify_login_token(&valid_key_a)
        .await
        .expect("verify key a after recovery");
    assert_eq!(claims_a.identity, "alice");
    assert_eq!(jwks_hits.load(Ordering::SeqCst), 2);

    rot_verifier.clear_refresh_backoff();
    let expired_key_a = jsonwebtoken::encode(
        &hdr,
        &json!({
            "iss": rot_issuer,
            "sub": "alice",
            "identity": "alice",
            "aud": ["https://lore.roguefairy.net"],
            "iat": 1_700_000_000_u64,
            "exp": 1_700_000_001_u64
        }),
        &rogue_enc,
    )
    .expect("expired key a");
    assert_eq!(
        rot_verifier.verify_login_token(&expired_key_a).await,
        Err(rfs_lore_bridge::error::AuthVerifyError::InvalidToken)
    );
    assert_eq!(
        jwks_hits.load(Ordering::SeqCst),
        2,
        "expired token with valid signature must not trigger JWKS refresh"
    );

    *active_jwks.write() = json!({
        "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "use": "sig",
            "kid": "rogue-kid",
            "x": xb,
            "y": yb
        }]
    });
    rot_verifier.clear_refresh_backoff();
    let rotated_token = jsonwebtoken::encode(
        &hdr,
        &json!({
            "iss": rot_issuer,
            "sub": "alice",
            "identity": "alice",
            "aud": ["https://lore.roguefairy.net"],
            "iat": 1_700_000_000_u64,
            "exp": 4_102_444_800_u64
        }),
        &enc_b,
    )
    .expect("rotated token");
    let shared_verifier = Arc::new(rot_verifier);
    let mut concurrent = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let v = shared_verifier.clone();
        let tok = rotated_token.clone();
        lore_spawn!(concurrent, async move { v.verify_login_token(&tok).await });
    }
    while let Some(joined) = concurrent.join_next().await {
        let claims_b = joined
            .expect("join rotation task")
            .expect("concurrent rotated key verification must succeed");
        assert_eq!(claims_b.identity, "alice");
    }
    assert_eq!(jwks_hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn uuid_user_id_field_token_form_validation_and_login_typ_guards() {
    let idp = MockAuthentik::spawn().await;
    let bridge = RunningBridge::spawn_with_user_id_field(&idp, UserIdField::Uuid).await;
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{}", bridge.addr))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect");
    let mut registry = RepositoryRegistryServiceClient::new(channel.clone());
    let mut users = UserServiceClient::new(channel);
    let http = reqwest::Client::new();

    let alice_uuid = "9a7b2c1d-0000-4000-8000-0000000000aa";
    let alice_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-alice",
            "identity": alice_uuid,
            "preferred_username": "alice",
            "name": "Alice C-Level",
            "rfs_lore": {
                "is_c_level": true,
                "is_employee": true,
                "can_create_any": true,
                "global_actions": ["read", "write", "owner", "admin", "migrate", "push-protected", "obliterate", "presign"],
                "projects": {}
            }
        }),
    );

    let ghost_id = repo_id("77777777777777777777777777777777");
    registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: ghost_id.into(),
                name: "ghostlore/uuid-test".to_owned(),
            },
            &alice_token,
        ))
        .await
        .expect("register ghostlore/uuid-test");

    let by_username = users
        .user_find(bearer_request(
            UserFindRequest {
                partition: ghost_id.into(),
                query: Some(FindQuery::Username("uuid_helena".to_owned())),
            },
            &alice_token,
        ))
        .await
        .expect("UserFind by username under uuid user_id_field")
        .into_inner()
        .user;
    assert_eq!(by_username.len(), 1);
    assert_eq!(by_username[0].id, "9a7b2c1d-0000-4000-8000-000000000001");
    assert_eq!(by_username[0].username, "uuid_helena");

    let by_id = users
        .user_get(bearer_request(
            UserGetRequest {
                partition: ghost_id.into(),
                id: vec!["9a7b2c1d-0000-4000-8000-000000000002".to_owned()],
            },
            &alice_token,
        ))
        .await
        .expect("UserGet by uuid")
        .into_inner()
        .user;
    assert_eq!(by_id.len(), 1);
    assert_eq!(by_id[0].id, "9a7b2c1d-0000-4000-8000-000000000002");
    assert_eq!(by_id[0].username, "uuid_igor");

    for bad_typ in ["logout+jwt", "at+jwt", "secevent+jwt"] {
        let non_login_jwt = idp.mint_token_with_typ(
            &idp.cli_issuer,
            Some(bad_typ),
            json!({
                "sub": "sub-alice",
                "identity": alice_uuid,
                "rfs_lore": { "is_c_level": true }
            }),
        );
        let err = registry
            .repository_list(bearer_request(RepositoryListRequest {}, &non_login_jwt))
            .await
            .expect_err("non-login JWT typ must be rejected");
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    let resource_uri = format!("https://lore.roguefairy.net/partitions/{ghost_id}");
    let dup_grant = http
        .post(format!("{}/token", bridge.base_url))
        .form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", alice_token.as_str()),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            ("resource", resource_uri.as_str()),
        ])
        .send()
        .await
        .expect("POST duplicate grant_type");
    assert_eq!(dup_grant.status(), 400);
    assert_eq!(
        dup_grant.json::<serde_json::Value>().await.expect("json")["error"],
        "invalid_request"
    );

    let bad_scope = http
        .post(format!("{}/token", bridge.base_url))
        .form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", alice_token.as_str()),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            ("resource", resource_uri.as_str()),
            ("scope", "admin"),
        ])
        .send()
        .await
        .expect("POST unsupported scope");
    assert_eq!(bad_scope.status(), 400);
    assert_eq!(
        bad_scope.json::<serde_json::Value>().await.expect("json")["error"],
        "invalid_scope"
    );

    let bad_audience = http
        .post(format!("{}/token", bridge.base_url))
        .form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", alice_token.as_str()),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            ("resource", resource_uri.as_str()),
            ("audience", "https://other.roguefairy.net"),
        ])
        .send()
        .await
        .expect("POST wrong audience");
    assert_eq!(bad_audience.status(), 400);
    assert_eq!(
        bad_audience
            .json::<serde_json::Value>()
            .await
            .expect("json")["error"],
        "invalid_target"
    );
}

#[tokio::test]
async fn non_ascii_jwt_typ_header_rejected_without_panic() {
    let idp = MockAuthentik::spawn().await;
    let bridge = RunningBridge::spawn(&idp).await;
    let mut registry = RepositoryRegistryServiceClient::connect(format!("http://{}", bridge.addr))
        .await
        .expect("connect registry");
    let http = reqwest::Client::new();

    // 14 bytes total; 2-byte UTF-8 '\u{00E9}' occupies byte indices 11..13, straddling index 12
    // ("application/".len()).
    let straddling_typ = "aaaaaaaaaaa\u{00E9}x";

    let login_weird_typ = idp.mint_token_with_typ(
        &idp.cli_issuer,
        Some(straddling_typ),
        json!({
            "sub": "sub-alice",
            "identity": "alice",
            "rfs_lore": { "is_c_level": true }
        }),
    );
    let err_login = registry
        .repository_list(bearer_request(RepositoryListRequest {}, &login_weird_typ))
        .await
        .expect_err("non-ASCII straddling typ on login issuer must be rejected cleanly");
    assert_eq!(err_login.code(), Code::Unauthenticated);

    let bridge_weird_typ = idp.mint_token_with_typ(
        &bridge.base_url,
        Some(straddling_typ),
        json!({
            "sub": "sub-alice",
            "identity": "alice"
        }),
    );
    let err_bridge = registry
        .repository_list(bearer_request(RepositoryListRequest {}, &bridge_weird_typ))
        .await
        .expect_err("non-ASCII straddling typ on bridge issuer must be rejected cleanly");
    assert_eq!(err_bridge.code(), Code::Unauthenticated);

    let tok_resp = http
        .post(format!("{}/token", bridge.base_url))
        .form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", login_weird_typ.as_str()),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            (
                "resource",
                "https://lore.roguefairy.net/partitions/11111111111111111111111111111111",
            ),
        ])
        .send()
        .await
        .expect("POST /token with straddling typ must not close connection on panic");
    assert_eq!(tok_resp.status(), 400);
}

#[tokio::test]
async fn partial_caller_group_and_user_service_inactive_batch_and_5xx_contracts() {
    let idp = MockAuthentik::spawn().await;
    let bridge = RunningBridge::spawn(&idp).await;
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{}", bridge.addr))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect");
    let mut registry = RepositoryRegistryServiceClient::new(channel.clone());
    let mut users = UserServiceClient::new(channel);

    // `partial_lead` belongs only to a secondary group on `confidential` that omitted
    // `lore_visibility` (defaulting to `internal` in their token), whereas `/api/v3/core/groups/`
    // defines `confidential` with `lore_visibility: restricted`.
    let partial_lead_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-partial-lead",
            "identity": "partial_lead",
            "preferred_username": "partial_lead",
            "name": "Partial Lead",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {
                    "confidential": {
                        "actions": ["read", "write"],
                        "can_create_repo": true,
                        "visibility": "internal"
                    },
                    "ghostlore": {
                        "actions": ["read", "write", "admin"],
                        "can_create_repo": true,
                        "visibility": "internal"
                    }
                }
            }
        }),
    );
    let bruno_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-bruno",
            "identity": "bruno",
            "preferred_username": "bruno",
            "name": "Bruno Dev",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {}
            }
        }),
    );

    idp.group_api_hits.store(0, Ordering::SeqCst);
    let conf_repo_id = repo_id("88888888888888888888888888888888");
    registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: conf_repo_id.into(),
                name: "confidential/subrepo".to_owned(),
            },
            &partial_lead_token,
        ))
        .await
        .expect("partial_lead registers confidential/subrepo");

    let ghost_repo_id = repo_id("99999999999999999999999999999999");
    registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: ghost_repo_id.into(),
                name: "ghostlore/tools".to_owned(),
            },
            &partial_lead_token,
        ))
        .await
        .expect("partial_lead registers ghostlore/tools");

    assert_eq!(
        idp.group_api_hits.load(Ordering::SeqCst),
        1,
        "group visibility cache must serve the second registration within TTL"
    );

    let mut bruno_stream = registry
        .repository_list(bearer_request(RepositoryListRequest {}, &bruno_token))
        .await
        .expect("bruno list")
        .into_inner();
    let mut bruno_seen = Vec::new();
    while let Some(item) = bruno_stream.next().await {
        bruno_seen.push(item.expect("stream item").id.to_vec());
    }
    assert_eq!(
        bruno_seen,
        vec![ghost_repo_id.as_ref().to_vec()],
        "confidential/subrepo must be registered as restricted even when caller only holds a partial internal group"
    );

    let inactive_got = users
        .user_get(bearer_request(
            UserGetRequest {
                partition: ghost_repo_id.into(),
                id: vec!["former_gina".to_owned()],
            },
            &bruno_token,
        ))
        .await
        .expect("UserGet inactive historical author")
        .into_inner()
        .user;
    assert_eq!(inactive_got.len(), 1);
    assert_eq!(inactive_got[0].display_name, "Gina Former Employee");

    let twenty_ids: Vec<String> = (0..20).map(|i| format!("batch_author_{i}")).collect();
    let batch_got = users
        .user_get(bearer_request(
            UserGetRequest {
                partition: ghost_repo_id.into(),
                id: twenty_ids,
            },
            &bruno_token,
        ))
        .await
        .expect("UserGet 20 uncached authors")
        .into_inner()
        .user;
    assert_eq!(
        batch_got.len(),
        20,
        "UserGet must resolve all 20 uncached authors without silent truncation at 16"
    );

    let by_display = users
        .user_find(bearer_request(
            UserFindRequest {
                partition: ghost_repo_id.into(),
                query: Some(FindQuery::DisplayName("Frank From Authentik".to_owned())),
            },
            &bruno_token,
        ))
        .await
        .expect("UserFind exact DisplayName via Authentik ?name=")
        .into_inner()
        .user;
    assert_eq!(by_display.len(), 1);
    assert_eq!(by_display[0].id, "uncached_frank");

    idp.user_api_hits.store(0, Ordering::SeqCst);
    for _ in 0..2 {
        let miss = users
            .user_find(bearer_request(
                UserFindRequest {
                    partition: ghost_repo_id.into(),
                    query: Some(FindQuery::DisplayName(
                        "Missing Display Name In Authentik".to_owned(),
                    )),
                },
                &bruno_token,
            ))
            .await
            .expect("UserFind DisplayName miss")
            .into_inner()
            .user;
        assert!(miss.is_empty());
    }
    assert_eq!(
        idp.user_api_hits.load(Ordering::SeqCst),
        1,
        "negative user cache must suppress repeated DisplayName misses"
    );

    idp.fail_users_503.store(true, Ordering::SeqCst);
    let err_503_get = users
        .user_get(bearer_request(
            UserGetRequest {
                partition: ghost_repo_id.into(),
                id: vec!["uncached_when_authentik_down".to_owned()],
            },
            &bruno_token,
        ))
        .await
        .expect_err("Authentik 503 on UserGet must return Unavailable, not empty Ok");
    assert_eq!(err_503_get.code(), Code::Unavailable);

    let err_503_find = users
        .user_find(bearer_request(
            UserFindRequest {
                partition: ghost_repo_id.into(),
                query: Some(FindQuery::Username(
                    "uncached_when_authentik_down".to_owned(),
                )),
            },
            &bruno_token,
        ))
        .await
        .expect_err("Authentik 503 on UserFind must return Unavailable, not empty Ok");
    assert_eq!(err_503_find.code(), Code::Unavailable);
}

#[tokio::test]
async fn split_listeners_expose_user_service_publicly_while_isolating_registry_to_grpc_bind() {
    let idp = MockAuthentik::spawn().await;
    let public_listener = bind_test_listener().await;
    let grpc_listener = bind_test_listener().await;
    let public_addr = public_listener.local_addr().expect("public addr");
    let grpc_addr = grpc_listener.local_addr().expect("grpc addr");
    let public_url = format!("http://{public_addr}");
    let grpc_url = format!("http://{grpc_addr}");

    let config = BridgeConfig {
        bind: public_addr.to_string(),
        grpc_bind: Some(grpc_addr.to_string()),
        issuer: public_url.clone(),
        provider_url: None,
        login_issuers: vec![idp.cli_issuer.clone(), idp.ci_issuer.clone()],
        login_audiences: vec!["https://lore.roguefairy.net".to_owned()],
        audience: "https://lore.roguefairy.net".to_owned(),
        root_domains: vec![
            ".roguefairy.net".to_owned(),
            "127.0.0.1".to_owned(),
            "localhost".to_owned(),
        ],
        resource_prefix: "https://lore.roguefairy.net/partitions/".to_owned(),
        resource_id_template: "urc-{id}".to_owned(),
        token_lifetime_seconds: 300,
        state_path: None,
        user_state_path: None,
        signing_key_path: None,
        signing_key_b64: None,
        authentik: AuthentikApiConfig {
            base_url: Some(idp.base_url.clone()),
            api_token: Some("test-authentik-api-token".to_owned()),
            user_id_field: UserIdField::Username,
        },
        policy: rfs_lore_bridge::config::PolicyConfig::default(),
        projects: BTreeMap::new(),
    };
    config.validate().expect("split config valid");

    let (signer, _) = TokenSigner::load_or_generate(None, None).expect("ephemeral signer");
    let verifier = TokenVerifier::new(config.clone(), signer.clone()).expect("verifier");
    let store = BridgeStore::open_with_user_id_field(None, config.authentik.user_id_field)
        .expect("in-memory store");
    let runtime = Arc::new(BridgeRuntime::new(config, signer, verifier, store));

    let public_app = build_public_router(runtime.clone());
    let grpc_app = GrpcBridgeService::new(runtime).into_axum_router();
    let _public_task =
        AbortOnDropHandle::new(lore_spawn!(serve_test_router(public_listener, public_app)));
    let _grpc_task =
        AbortOnDropHandle::new(lore_spawn!(serve_test_router(grpc_listener, grpc_app)));

    let lead_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-carla",
            "identity": "carla",
            "preferred_username": "carla",
            "name": "Carla Lead",
            "email": "carla@roguefairy.net",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {
                    "ghostlore": {
                        "actions": ["read", "write", "admin"],
                        "can_create_repo": true,
                        "visibility": "internal"
                    }
                }
            }
        }),
    );
    let ghost_id = repo_id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    // 1. Public listener must reject RepositoryRegistryService calls.
    let mut public_registry = RepositoryRegistryServiceClient::connect(public_url.clone())
        .await
        .expect("connect public registry client");
    let pub_reg_err = public_registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: ghost_id.into(),
                name: "ghostlore/game".to_owned(),
            },
            &lead_token,
        ))
        .await
        .expect_err("public listener must not expose RepositoryRegistryService");
    assert_eq!(pub_reg_err.code(), Code::Unimplemented);

    // 2. Internal gRPC listener registers the repository.
    let mut internal_registry = RepositoryRegistryServiceClient::connect(grpc_url)
        .await
        .expect("connect internal registry client");
    internal_registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: ghost_id.into(),
                name: "ghostlore/game".to_owned(),
            },
            &lead_token,
        ))
        .await
        .expect("internal listener registers ghostlore/game");

    // 3. Public listener serves HTTP OIDC endpoints AND UserService for external CLI clients.
    let http_client = reqwest::Client::new();
    let health = http_client
        .get(format!("{public_url}/health_check"))
        .send()
        .await
        .expect("GET /health_check");
    assert_eq!(health.status(), reqwest::StatusCode::OK);

    let mut public_users = UserServiceClient::connect(public_url)
        .await
        .expect("connect public UserService client");
    let got = public_users
        .user_get(bearer_request(
            UserGetRequest {
                partition: ghost_id.into(),
                id: vec!["carla".to_owned()],
            },
            &lead_token,
        ))
        .await
        .expect("public listener must serve UserService::UserGet")
        .into_inner()
        .user;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].display_name, "Carla Lead");
}

#[tokio::test]
async fn group_cache_fails_closed_on_missing_project_and_outage_throttle() {
    let idp = MockAuthentik::spawn().await;
    let bridge = RunningBridge::spawn(&idp).await;
    let mut registry = RepositoryRegistryServiceClient::connect(format!("http://{}", bridge.addr))
        .await
        .expect("connect registry");

    let stale_lead_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-stale-lead",
            "identity": "stale_lead",
            "preferred_username": "stale_lead",
            "name": "Stale Lead",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {
                    "ghostlore": {
                        "actions": ["read", "write", "admin"],
                        "can_create_repo": true,
                        "visibility": "internal"
                    },
                    "deletedproj": {
                        "actions": ["read", "write"],
                        "can_create_repo": true,
                        "visibility": "internal"
                    },
                    "promotable": {
                        "actions": ["read", "write"],
                        "can_create_repo": true,
                        "visibility": "internal"
                    }
                }
            }
        }),
    );

    let alice_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-alice",
            "identity": "alice",
            "preferred_username": "alice",
            "name": "Alice C-Level",
            "rfs_lore": {
                "is_c_level": true,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": true,
                "global_actions": ["read", "write", "owner", "admin", "migrate", "push-protected", "obliterate", "presign"],
                "projects": {}
            }
        }),
    );

    // Populate group cache with initial healthy response (`ghostlore` + `confidential`).
    registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: repo_id("12121212121212121212121212121212").into(),
                name: "ghostlore/init".to_owned(),
            },
            &stale_lead_token,
        ))
        .await
        .expect("register ghostlore/init");

    // Project absent from `/api/v3/core/groups/` must fail closed with `NotFound` even when
    // the caller's token carries `can_create_repo: true` and `visibility: "internal"`, and must
    // remain throttled for `MIN_REFRESH_INTERVAL` (10s), not 1s.
    let hits_before_miss = idp.group_api_hits.load(Ordering::SeqCst);
    bridge
        .runtime
        .verifier
        .backdate_group_attempt(std::time::Duration::from_millis(1100));
    let absent_err = registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: repo_id("13131313131313131313131313131313").into(),
                name: "deletedproj/main".to_owned(),
            },
            &stale_lead_token,
        ))
        .await
        .expect_err("project absent from authentik groups must fail closed");
    assert_eq!(absent_err.code(), Code::NotFound);
    assert_eq!(
        idp.group_api_hits.load(Ordering::SeqCst),
        hits_before_miss,
        "missing project lookup after 1.1s must stay throttled within MIN_REFRESH_INTERVAL (10s)"
    );

    // Simulate authentik `/api/v3/core/groups/` 503 after an earlier 200. Both the first
    // refresh attempt AND an immediate retry within `MIN_REFRESH_INTERVAL` must return `Unavailable`.
    bridge.runtime.verifier.clear_refresh_backoff();
    idp.fail_groups_503.store(true, Ordering::SeqCst);

    let outage_first = registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: repo_id("14141414141414141414141414141414").into(),
                name: "newoutageproj/main".to_owned(),
            },
            &alice_token,
        ))
        .await
        .expect_err("first registration during authentik 503 must fail");
    assert_eq!(outage_first.code(), Code::Unavailable);

    let outage_second = registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: repo_id("14141414141414141414141414141414").into(),
                name: "newoutageproj/main".to_owned(),
            },
            &alice_token,
        ))
        .await
        .expect_err("throttled retry during authentik 503 must stay Unavailable, never NotFound");
    assert_eq!(outage_second.code(), Code::Unavailable);

    // Expired `Internal` entry (`promotable`) must also fail closed with `Unavailable` during
    // a 503 outage, both on the refresh attempt and on throttled retries within 10s.
    bridge.runtime.verifier.expire_group_cache_ttl();
    for _ in 0..2 {
        let expired_outage = registry
            .repository_register(bearer_request(
                RepositoryRegisterRequest {
                    id: repo_id("15151515151515151515151515151515").into(),
                    name: "promotable/main".to_owned(),
                },
                &stale_lead_token,
            ))
            .await
            .expect_err("expired group cache entry must never fail open during authentik 503");
        assert_eq!(expired_outage.code(), Code::Unavailable);
    }
}

#[tokio::test]
async fn uuid_mode_user_get_skips_non_uuid_ids_without_400_unavailable() {
    let idp = MockAuthentik::spawn().await;
    let bridge = RunningBridge::spawn_with_user_id_field(&idp, UserIdField::Uuid).await;
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{}", bridge.addr))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect");
    let mut registry = RepositoryRegistryServiceClient::new(channel.clone());
    let mut users = UserServiceClient::new(channel);

    let alice_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "9a7b2c1d-0000-4000-8000-0000000000aa",
            "identity": "9a7b2c1d-0000-4000-8000-0000000000aa",
            "preferred_username": "alice",
            "name": "Alice UUID",
            "rfs_lore": {
                "is_c_level": true,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": true,
                "global_actions": ["read", "write", "owner", "admin", "migrate", "push-protected", "obliterate", "presign"],
                "projects": {}
            }
        }),
    );

    let ghost_id = repo_id("21212121212121212121212121212121");
    registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: ghost_id.into(),
                name: "ghostlore/uuid-batch".to_owned(),
            },
            &alice_token,
        ))
        .await
        .expect("register ghostlore/uuid-batch");

    idp.user_api_hits.store(0, Ordering::SeqCst);
    let resolved = users
        .user_get(bearer_request(
            UserGetRequest {
                partition: ghost_id.into(),
                id: vec![
                    "9a7b2c1d-0000-4000-8000-000000000002".to_owned(),
                    "legacy_username_author".to_owned(),
                ],
            },
            &alice_token,
        ))
        .await
        .expect(
            "non-UUID id in uuid mode must be omitted cleanly, not fail batch with 400/Unavailable",
        )
        .into_inner()
        .user;
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].id, "9a7b2c1d-0000-4000-8000-000000000002");
    assert_eq!(resolved[0].username, "uuid_igor");
    assert_eq!(
        idp.user_api_hits.load(Ordering::SeqCst),
        1,
        "only the syntactic UUID must be queried against authentik ?uuid="
    );
}

#[tokio::test]
async fn jwks_outage_after_prior_cache_returns_unavailable_for_unknown_kid_while_serving_cached_kid()
 {
    let idp = MockAuthentik::spawn().await;
    let bridge = RunningBridge::spawn(&idp).await;
    let mut registry = RepositoryRegistryServiceClient::connect(format!("http://{}", bridge.addr))
        .await
        .expect("connect registry");
    let http = reqwest::Client::new();

    let claims = json!({
        "sub": "sub-bruno",
        "identity": "bruno",
        "preferred_username": "bruno",
        "name": "Bruno Dev",
        "rfs_lore": {
            "is_c_level": false,
            "is_employee": true,
            "is_partner": false,
            "can_create_any": false,
            "global_actions": [],
            "projects": {}
        }
    });
    let cached_kid_token = idp.mint_login_token(&idp.cli_issuer, claims.clone());
    let rotated_kid_token = idp.mint_login_token_with_kid(&idp.cli_issuer, "rotated-kid-2", claims);

    // Warm IssuerKeyCache with `kid-1`.
    registry
        .repository_list(bearer_request(RepositoryListRequest {}, &cached_kid_token))
        .await
        .expect("initial RepositoryList caches kid-1");

    // Simulate JWKS 503 during key rotation.
    bridge.runtime.verifier.clear_refresh_backoff();
    idp.fail_jwks_503.store(true, Ordering::SeqCst);

    // Already-cached `kid-1` continues succeeding.
    registry
        .repository_list(bearer_request(RepositoryListRequest {}, &cached_kid_token))
        .await
        .expect("cached kid-1 must continue succeeding during JWKS outage");

    // Unknown `rotated-kid-2` must receive `Unavailable` (and HTTP 503 on `/token`),
    // both on the initial refresh failure and on throttled retries within `MIN_REFRESH_INTERVAL`.
    let grpc_err_1 = registry
        .repository_list(bearer_request(RepositoryListRequest {}, &rotated_kid_token))
        .await
        .expect_err("rotated kid during JWKS 503 must fail");
    assert_eq!(grpc_err_1.code(), Code::Unavailable);

    let tok_resp = http
        .post(format!("{}/token", bridge.base_url))
        .form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", rotated_kid_token.as_str()),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            (
                "resource",
                "https://lore.roguefairy.net/partitions/11111111111111111111111111111111",
            ),
        ])
        .send()
        .await
        .expect("POST /token during JWKS 503");
    assert_eq!(tok_resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn display_name_user_find_paginates_past_first_page() {
    let idp = MockAuthentik::spawn().await;
    let bridge = RunningBridge::spawn(&idp).await;
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{}", bridge.addr))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect");
    let mut registry = RepositoryRegistryServiceClient::new(channel.clone());
    let mut users = UserServiceClient::new(channel);

    let alice_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-alice",
            "identity": "alice",
            "preferred_username": "alice",
            "name": "Alice C-Level",
            "rfs_lore": {
                "is_c_level": true,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": true,
                "global_actions": ["read", "write", "owner", "admin", "migrate", "push-protected", "obliterate", "presign"],
                "projects": {}
            }
        }),
    );
    let ghost_id = repo_id("31313131313131313131313131313131");
    registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: ghost_id.into(),
                name: "ghostlore/paginated-users".to_owned(),
            },
            &alice_token,
        ))
        .await
        .expect("register ghostlore/paginated-users");

    let matched = users
        .user_find(bearer_request(
            UserFindRequest {
                partition: ghost_id.into(),
                query: Some(FindQuery::DisplayName(
                    "Paginated Display Target".to_owned(),
                )),
            },
            &alice_token,
        ))
        .await
        .expect("UserFind DisplayName across pages")
        .into_inner()
        .user;
    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0].id, "page2_paula");
}

fn normalize_test_uuid_hex(raw: &str) -> Option<String> {
    if !is_test_syntactic_uuid(raw) {
        return None;
    }
    Some(
        raw.bytes()
            .filter(|b| *b != b'-')
            .map(|b| char::from(b.to_ascii_lowercase()))
            .collect(),
    )
}

#[tokio::test]
async fn user_directory_bounds_oversized_and_control_queries_and_matches_canonical_uuids() {
    let idp = MockAuthentik::spawn().await;
    let uuid_bridge = RunningBridge::spawn_with_user_id_field(&idp, UserIdField::Uuid).await;
    let uuid_channel =
        tonic::transport::Endpoint::from_shared(format!("http://{}", uuid_bridge.addr))
            .expect("uuid endpoint")
            .connect()
            .await
            .expect("connect uuid bridge");
    let mut uuid_registry = RepositoryRegistryServiceClient::new(uuid_channel.clone());
    let mut uuid_users = UserServiceClient::new(uuid_channel);

    let alice_uuid_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "9a7b2c1d-0000-4000-8000-0000000000aa",
            "identity": "9a7b2c1d-0000-4000-8000-0000000000aa",
            "preferred_username": "alice",
            "name": "Alice UUID",
            "rfs_lore": {
                "is_c_level": true,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": true,
                "global_actions": ["read", "write", "owner", "admin", "migrate", "push-protected", "obliterate", "presign"],
                "projects": {}
            }
        }),
    );

    let uuid_repo = repo_id("31313131313131313131313131313131");
    uuid_registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: uuid_repo.into(),
                name: "ghostlore/uuid-forms".to_owned(),
            },
            &alice_uuid_token,
        ))
        .await
        .expect("register ghostlore/uuid-forms");

    idp.user_api_hits.store(0, Ordering::SeqCst);
    let resolved_uuids = uuid_users
        .user_get(bearer_request(
            UserGetRequest {
                partition: uuid_repo.into(),
                id: vec![
                    "9a7b2c1d000040008000000000000002".to_owned(),
                    "9A7B2C1D-0000-4000-8000-000000000002".to_owned(),
                ],
            },
            &alice_uuid_token,
        ))
        .await
        .expect("32-char hex and uppercase UUIDs must resolve")
        .into_inner()
        .user;
    assert_eq!(resolved_uuids.len(), 2);
    assert_eq!(resolved_uuids[0].id, "9a7b2c1d000040008000000000000002");
    assert_eq!(resolved_uuids[0].username, "uuid_igor");
    assert_eq!(resolved_uuids[1].id, "9A7B2C1D-0000-4000-8000-000000000002");
    assert_eq!(resolved_uuids[1].username, "uuid_igor");
    assert_eq!(
        idp.user_api_hits.load(Ordering::SeqCst),
        1,
        "compact and hyphenated representations of the same UUID must deduplicate to one authentik query"
    );

    let cached_uuids = uuid_users
        .user_get(bearer_request(
            UserGetRequest {
                partition: uuid_repo.into(),
                id: vec![
                    "9a7b2c1d000040008000000000000002".to_owned(),
                    "9A7B2C1D-0000-4000-8000-000000000002".to_owned(),
                ],
            },
            &alice_uuid_token,
        ))
        .await
        .expect("cached UUID lookup must succeed")
        .into_inner()
        .user;
    assert_eq!(cached_uuids.len(), 2);
    assert_eq!(cached_uuids[0].id, "9a7b2c1d000040008000000000000002");
    assert_eq!(
        cached_uuids[0].username, "uuid_igor",
        "caching multiple UUID formats must not wipe stored username"
    );
    assert_eq!(cached_uuids[1].id, "9A7B2C1D-0000-4000-8000-000000000002");
    assert_eq!(cached_uuids[1].username, "uuid_igor");
    assert_eq!(idp.user_api_hits.load(Ordering::SeqCst), 1);

    let igor_by_display = uuid_users
        .user_find(bearer_request(
            UserFindRequest {
                partition: uuid_repo.into(),
                query: Some(FindQuery::DisplayName("Igor UUID".to_owned())),
            },
            &alice_uuid_token,
        ))
        .await
        .expect("UserFind DisplayName for Igor UUID")
        .into_inner()
        .user;
    assert_eq!(
        igor_by_display.len(),
        1,
        "canonical UUID storage must not duplicate display_name index entries"
    );
    assert_eq!(igor_by_display[0].username, "uuid_igor");

    // In default `username` mode, oversized and control-char queries must be dropped locally
    // without triggering HTTP 414/400 -> `Code::Unavailable` or poisoning `NegativeUserCache`.
    let uname_bridge = RunningBridge::spawn(&idp).await;
    let uname_channel =
        tonic::transport::Endpoint::from_shared(format!("http://{}", uname_bridge.addr))
            .expect("uname endpoint")
            .connect()
            .await
            .expect("connect uname bridge");
    let mut uname_registry = RepositoryRegistryServiceClient::new(uname_channel.clone());
    let mut uname_users = UserServiceClient::new(uname_channel);

    let alice_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-alice",
            "identity": "alice",
            "preferred_username": "alice",
            "name": "Alice C-Level",
            "rfs_lore": {
                "is_c_level": true,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": true,
                "global_actions": ["read", "write", "owner", "admin", "migrate", "push-protected", "obliterate", "presign"],
                "projects": {}
            }
        }),
    );
    let uname_repo = repo_id("32323232323232323232323232323232");
    uname_registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: uname_repo.into(),
                name: "ghostlore/uname-bounds".to_owned(),
            },
            &alice_token,
        ))
        .await
        .expect("register ghostlore/uname-bounds");

    idp.user_api_hits.store(0, Ordering::SeqCst);
    let batch = uname_users
        .user_get(bearer_request(
            UserGetRequest {
                partition: uname_repo.into(),
                id: vec![
                    "x".repeat(2048),
                    "bad\0id".to_owned(),
                    "uncached_frank".to_owned(),
                ],
            },
            &alice_token,
        ))
        .await
        .expect("oversized and control-char UserGet entries must not fail batch with Unavailable")
        .into_inner()
        .user;
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].username, "uncached_frank");
    assert_eq!(
        idp.user_api_hits.load(Ordering::SeqCst),
        1,
        "only valid bounded ids may hit authentik /api/v3/core/users/"
    );

    for query in [
        FindQuery::Username("u".repeat(2048)),
        FindQuery::Username("bad\nuser".to_owned()),
        FindQuery::DisplayName("d".repeat(2048)),
        FindQuery::DisplayName("bad\0display".to_owned()),
    ] {
        let found = uname_users
            .user_find(bearer_request(
                UserFindRequest {
                    partition: uname_repo.into(),
                    query: Some(query),
                },
                &alice_token,
            ))
            .await
            .expect("oversized or control-char UserFind must return empty Ok, not Unavailable")
            .into_inner()
            .user;
        assert!(found.is_empty());
    }
    assert_eq!(idp.user_api_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn aged_issuer_cache_serves_cached_kid_without_blocking_on_slow_jwks() {
    let idp = MockAuthentik::spawn().await;
    let bridge = RunningBridge::spawn(&idp).await;
    let mut registry = RepositoryRegistryServiceClient::connect(format!("http://{}", bridge.addr))
        .await
        .expect("connect registry");

    let claims = json!({
        "sub": "sub-bruno",
        "identity": "bruno",
        "preferred_username": "bruno",
        "name": "Bruno Dev",
        "rfs_lore": {
            "is_c_level": false,
            "is_employee": true,
            "is_partner": false,
            "can_create_any": false,
            "global_actions": [],
            "projects": {}
        }
    });
    let cached_kid_token = idp.mint_login_token(&idp.cli_issuer, claims.clone());
    let unknown_kid_token =
        idp.mint_login_token_with_kid(&idp.cli_issuer, "slow-unknown-kid", claims);

    registry
        .repository_list(bearer_request(RepositoryListRequest {}, &cached_kid_token))
        .await
        .expect("warm kid-1");

    bridge
        .runtime
        .verifier
        .backdate_issuer_cache(std::time::Duration::from_secs(601));
    let (entered_rx, release_tx) = idp.park_next_jwks_fetch();

    let mut slow_client = registry.clone();
    let slow_handle = lore_spawn!(async move {
        let _ = slow_client
            .repository_list(bearer_request(RepositoryListRequest {}, &unknown_kid_token))
            .await;
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered_rx)
        .await
        .expect("slow refresh must enter /jwks/ handler")
        .expect("entered_tx sent");

    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        registry.repository_list(bearer_request(RepositoryListRequest {}, &cached_kid_token)),
    )
    .await
    .expect("cached kid must not block behind refresh_gate during parked JWKS refresh")
    .expect("cached kid RepositoryList must succeed");

    let _ = release_tx.send(());
    let _ = slow_handle.await;
}

#[tokio::test]
async fn unauthorized_requests_do_not_persist_caller_into_user_directory() {
    let idp = MockAuthentik::spawn().await;
    let bridge = RunningBridge::spawn(&idp).await;
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{}", bridge.addr))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect");
    let mut registry = RepositoryRegistryServiceClient::new(channel.clone());
    let mut users = UserServiceClient::new(channel);
    let http = reqwest::Client::new();

    let alice_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-alice",
            "identity": "alice",
            "preferred_username": "alice",
            "name": "Alice C-Level",
            "rfs_lore": {
                "is_c_level": true,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": true,
                "global_actions": ["read", "write", "owner", "admin", "migrate", "push-protected", "obliterate", "presign"],
                "projects": {}
            }
        }),
    );
    let ghost_id = repo_id("41414141414141414141414141414141");
    registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: ghost_id.into(),
                name: "ghostlore/protected-dir".to_owned(),
            },
            &alice_token,
        ))
        .await
        .expect("register ghostlore/protected-dir");

    let eva_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-eva-unauth",
            "identity": "eva_unauth",
            "preferred_username": "eva_unauth",
            "name": "Eva Unauthorized Partner",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": false,
                "is_partner": true,
                "can_create_any": false,
                "global_actions": [],
                "projects": {}
            }
        }),
    );

    let tok_resp = http
        .post(format!("{}/token", bridge.base_url))
        .form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", eva_token.as_str()),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            (
                "resource",
                "https://lore.roguefairy.net/partitions/41414141414141414141414141414141",
            ),
        ])
        .send()
        .await
        .expect("POST /token as eva_unauth");
    assert_eq!(tok_resp.status(), reqwest::StatusCode::BAD_REQUEST);

    assert_eq!(
        registry
            .repository_register(bearer_request(
                RepositoryRegisterRequest {
                    id: repo_id("42424242424242424242424242424242").into(),
                    name: "ghostlore/eva-attempt".to_owned(),
                },
                &eva_token,
            ))
            .await
            .expect_err("eva register denied")
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        registry
            .repository_unregister(bearer_request(
                RepositoryUnregisterRequest {
                    id: ghost_id.into(),
                },
                &eva_token,
            ))
            .await
            .expect_err("eva unregister denied")
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        users
            .user_get(bearer_request(
                UserGetRequest {
                    partition: ghost_id.into(),
                    id: vec!["alice".to_owned()],
                },
                &eva_token,
            ))
            .await
            .expect_err("eva user_get denied")
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        users
            .user_find(bearer_request(
                UserFindRequest {
                    partition: ghost_id.into(),
                    query: Some(FindQuery::Username("alice".to_owned())),
                },
                &eva_token,
            ))
            .await
            .expect_err("eva user_find denied")
            .code(),
        Code::PermissionDenied
    );
    let listed: Vec<_> = registry
        .repository_list(bearer_request(RepositoryListRequest {}, &eva_token))
        .await
        .expect("eva empty list")
        .into_inner()
        .collect()
        .await;
    assert!(listed.is_empty());

    assert!(
        bridge
            .runtime
            .store
            .find_by_username("eva_unauth")
            .is_empty(),
        "ungranted or rejected caller must never be persisted to the user directory"
    );
}

#[tokio::test]
async fn uuid_mode_canonicalizes_login_and_exchanged_identities_and_creator_unregister() {
    let idp = MockAuthentik::spawn().await;
    let bridge = RunningBridge::spawn_with_user_id_field(&idp, UserIdField::Uuid).await;
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{}", bridge.addr))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect");
    let mut registry = RepositoryRegistryServiceClient::new(channel.clone());
    let mut users = UserServiceClient::new(channel);
    let http = reqwest::Client::new();

    // Non-UUID login `identity` must fail verification in `UserIdField::Uuid` mode.
    let misconfigured_username_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "9a7b2c1d-0000-4000-8000-0000000000dd",
            "identity": "carla_username_not_uuid",
            "preferred_username": "carla",
            "name": "Carla Misconfigured",
            "rfs_lore": {
                "is_c_level": true,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": true,
                "global_actions": ["read", "write", "owner", "admin"],
                "projects": {}
            }
        }),
    );
    let list_err = registry
        .repository_list(bearer_request(
            RepositoryListRequest {},
            &misconfigured_username_token,
        ))
        .await
        .expect_err("non-UUID identity must be rejected in UserIdField::Uuid mode");
    assert_eq!(list_err.code(), Code::Unauthenticated);

    // Compact 32-hex UUID login token from creator holding `write` + `can_create_repo` (no `admin`/`owner`).
    let compact_creator_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "9a7b2c1d0000400080000000000000cc",
            "identity": "9a7b2c1d0000400080000000000000cc",
            "preferred_username": "carla_uuid",
            "name": "Carla UUID Creator",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {
                    "ghostlore": {
                        "actions": ["read", "write"],
                        "can_create_repo": true,
                        "visibility": "internal"
                    }
                }
            }
        }),
    );
    let repo = repo_id("51515151515151515151515151515151");
    registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: repo.into(),
                name: "ghostlore/creator-uuid".to_owned(),
            },
            &compact_creator_token,
        ))
        .await
        .expect("register ghostlore/creator-uuid");

    let tok_resp = http
        .post(format!("{}/token", bridge.base_url))
        .form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", compact_creator_token.as_str()),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            (
                "resource",
                "https://lore.roguefairy.net/partitions/51515151515151515151515151515151",
            ),
        ])
        .send()
        .await
        .expect("POST /token for compact UUID creator");
    assert_eq!(tok_resp.status(), reqwest::StatusCode::OK);
    let tok_json: serde_json::Value = tok_resp.json().await.expect("token json");
    let exchanged_jwt = tok_json["access_token"].as_str().expect("access_token");
    let mut val = Validation::new(Algorithm::ES256);
    val.set_issuer(std::slice::from_ref(&bridge.base_url));
    val.set_audience(&["https://lore.roguefairy.net"]);
    let decoded = decode::<ExchangedTokenClaims>(exchanged_jwt, bridge.signer.decoding_key(), &val)
        .expect("decode exchanged jwt");
    assert_eq!(
        decoded.claims.identity, "9a7b2c1d-0000-4000-8000-0000000000cc",
        "exchanged at+jwt identity must be canonical 36-char lowercase hyphenated UUID"
    );

    let by_uname = users
        .user_find(bearer_request(
            UserFindRequest {
                partition: repo.into(),
                query: Some(FindQuery::Username("carla_uuid".to_owned())),
            },
            exchanged_jwt,
        ))
        .await
        .expect("UserFind Username for carla_uuid")
        .into_inner()
        .user;
    assert_eq!(by_uname.len(), 1);
    assert_eq!(by_uname[0].id, "9a7b2c1d-0000-4000-8000-0000000000cc");

    let upper_creator_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "9A7B2C1D-0000-4000-8000-0000000000CC",
            "identity": "9A7B2C1D-0000-4000-8000-0000000000CC",
            "preferred_username": "carla_uuid",
            "name": "Carla UUID Creator",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {
                    "ghostlore": {
                        "actions": ["read", "write"],
                        "can_create_repo": true,
                        "visibility": "internal"
                    }
                }
            }
        }),
    );
    registry
        .repository_unregister(bearer_request(
            RepositoryUnregisterRequest { id: repo.into() },
            &upper_creator_token,
        ))
        .await
        .expect(
            "creator holding write must unregister across compact/uppercase/hyphenated UUID forms",
        );
}

#[tokio::test]
async fn negative_user_cache_evicts_oldest_without_full_wipe_and_user_get_preserves_local_hits() {
    use rfs_lore_bridge::grpc::MAX_USER_GET_IDS;
    use rfs_lore_bridge::jwks::MAX_NEGATIVE_USER_CACHE_ENTRIES;

    let idp = MockAuthentik::spawn().await;
    let bridge = RunningBridge::spawn(&idp).await;
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{}", bridge.addr))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect");
    let mut registry = RepositoryRegistryServiceClient::new(channel.clone());
    let mut users = UserServiceClient::new(channel);

    let alice_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-alice",
            "identity": "alice",
            "preferred_username": "alice",
            "name": "Alice C-Level",
            "rfs_lore": {
                "is_c_level": true,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": true,
                "global_actions": ["read", "write", "owner", "admin", "migrate", "push-protected", "obliterate", "presign"],
                "projects": {}
            }
        }),
    );
    let ghost_id = repo_id("52525252525252525252525252525252");
    registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: ghost_id.into(),
                name: "ghostlore/neg-cache".to_owned(),
            },
            &alice_token,
        ))
        .await
        .expect("register ghostlore/neg-cache");

    assert_eq!(MAX_USER_GET_IDS, 4096);
    let over_batch: Vec<String> = (0..=MAX_USER_GET_IDS).map(|i| format!("u_{i}")).collect();
    let over_err = users
        .user_get(bearer_request(
            UserGetRequest {
                partition: ghost_id.into(),
                id: over_batch,
            },
            &alice_token,
        ))
        .await
        .expect_err("UserGet past MAX_USER_GET_IDS must fail with InvalidArgument");
    assert_eq!(over_err.code(), Code::InvalidArgument);

    // Insert `MAX_NEGATIVE_USER_CACHE_ENTRIES + 8` misses so the negative cache overflows by 8.
    let total_misses = MAX_NEGATIVE_USER_CACHE_ENTRIES + 8;
    let all_misses: Vec<String> = (0..total_misses).map(|i| format!("neg_miss_{i}")).collect();
    for chunk in all_misses.chunks(64) {
        let got = users
            .user_get(bearer_request(
                UserGetRequest {
                    partition: ghost_id.into(),
                    id: chunk.to_vec(),
                },
                &alice_token,
            ))
            .await
            .expect("UserGet miss chunk")
            .into_inner()
            .user;
        assert!(got.is_empty());
    }

    // Middle and newest misses (`neg_miss_2048` and `neg_miss_4096..4104`) must remain cached
    // without triggering any upstream HTTP hits (proving overflow didn't `clear()` the map).
    idp.user_api_hits.store(0, Ordering::SeqCst);
    let mut retained_probe = vec!["neg_miss_2048".to_owned()];
    for i in MAX_NEGATIVE_USER_CACHE_ENTRIES..total_misses {
        retained_probe.push(format!("neg_miss_{i}"));
    }
    let retained_res = users
        .user_get(bearer_request(
            UserGetRequest {
                partition: ghost_id.into(),
                id: retained_probe,
            },
            &alice_token,
        ))
        .await
        .expect("retained negative cache probe")
        .into_inner()
        .user;
    assert!(retained_res.is_empty());
    assert_eq!(
        idp.user_api_hits.load(Ordering::SeqCst),
        0,
        "overflowing NegativeUserCache must evict oldest entries rather than wiping all entries"
    );

    // The oldest entry (`neg_miss_0`) must have been evicted to hold capacity at 4096.
    let evicted_res = users
        .user_get(bearer_request(
            UserGetRequest {
                partition: ghost_id.into(),
                id: vec!["neg_miss_0".to_owned()],
            },
            &alice_token,
        ))
        .await
        .expect("evicted oldest negative cache probe")
        .into_inner()
        .user;
    assert!(evicted_res.is_empty());
    assert_eq!(
        idp.user_api_hits.load(Ordering::SeqCst),
        1,
        "evicted oldest miss must re-query authentik once"
    );

    // During an authentik 503 outage, a mixed `UserGet` with a locally cached user (`alice`)
    // and an uncached user must still return `alice`, whereas an all-uncached `UserGet` returns `Unavailable`.
    idp.fail_users_503.store(true, Ordering::SeqCst);
    let partial = users
        .user_get(bearer_request(
            UserGetRequest {
                partition: ghost_id.into(),
                id: vec!["alice".to_owned(), "uncached_during_503".to_owned()],
            },
            &alice_token,
        ))
        .await
        .expect("mixed local+uncached UserGet during 503 must return locally cached users")
        .into_inner()
        .user;
    assert_eq!(partial.len(), 1);
    assert_eq!(partial[0].id, "alice");

    let all_missing_503 = users
        .user_get(bearer_request(
            UserGetRequest {
                partition: ghost_id.into(),
                id: vec!["only_uncached_during_503".to_owned()],
            },
            &alice_token,
        ))
        .await
        .expect_err("all-uncached UserGet during 503 must return Unavailable");
    assert_eq!(all_missing_503.code(), Code::Unavailable);
}

#[tokio::test]
async fn user_get_handles_large_duplicate_and_local_batches_caps_upstream_and_keeps_partial_fetches()
 {
    use rfs_lore_bridge::store::UserRecord;

    let idp = MockAuthentik::spawn().await;
    let bridge = RunningBridge::spawn(&idp).await;
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{}", bridge.addr))
        .expect("endpoint")
        .connect()
        .await
        .expect("connect");
    let mut registry = RepositoryRegistryServiceClient::new(channel.clone());
    let mut users = UserServiceClient::new(channel);

    let alice_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-alice",
            "identity": "alice",
            "preferred_username": "alice",
            "name": "Alice C-Level",
            "rfs_lore": {
                "is_c_level": true,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": true,
                "global_actions": ["read", "write", "owner", "admin", "migrate", "push-protected", "obliterate", "presign"],
                "projects": {}
            }
        }),
    );
    let ghost_id = repo_id("53535353535353535353535353535353");
    registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: ghost_id.into(),
                name: "ghostlore/lock-and-history-scale".to_owned(),
            },
            &alice_token,
        ))
        .await
        .expect("register ghostlore/lock-and-history-scale");

    // 1. Un-deduplicated `lore lock list` batch of 300 identical lock owners must succeed.
    let dup_locks = vec!["alice".to_owned(); 300];
    let dup_got = users
        .user_get(bearer_request(
            UserGetRequest {
                partition: ghost_id.into(),
                id: dup_locks,
            },
            &alice_token,
        ))
        .await
        .expect("300 duplicate lock owners must resolve")
        .into_inner()
        .user;
    assert_eq!(dup_got.len(), 1);
    assert_eq!(dup_got[0].id, "alice");

    // 2. `lore history` batch of 160 distinct locally cached authors must return all 160 with 0 upstream hits.
    let local_authors: Vec<UserRecord> = (0..160)
        .map(|i| UserRecord {
            id: format!("cached_hist_{i}"),
            username: format!("cached_hist_{i}"),
            display_name: format!("Cached Author {i}"),
        })
        .collect();
    bridge
        .runtime
        .store
        .upsert_users(&local_authors)
        .await
        .expect("seed 160 local authors");
    idp.user_api_hits.store(0, Ordering::SeqCst);
    let local_got = users
        .user_get(bearer_request(
            UserGetRequest {
                partition: ghost_id.into(),
                id: local_authors.iter().map(|u| u.id.clone()).collect(),
            },
            &alice_token,
        ))
        .await
        .expect("160 cached historical authors must resolve locally")
        .into_inner()
        .user;
    assert_eq!(local_got.len(), 160);
    assert_eq!(idp.user_api_hits.load(Ordering::SeqCst), 0);

    // 3. Batch of 200 distinct uncached IDs must cap outbound authentik HTTP fanout at 128 per RPC.
    idp.user_api_hits.store(0, Ordering::SeqCst);
    let uncached_200: Vec<String> = (0..200).map(|i| format!("uncached_fanout_{i}")).collect();
    let _ = users
        .user_get(bearer_request(
            UserGetRequest {
                partition: ghost_id.into(),
                id: uncached_200,
            },
            &alice_token,
        ))
        .await
        .expect("200 uncached UserGet must succeed with bounded fanout");
    assert_eq!(
        idp.user_api_hits.load(Ordering::SeqCst),
        128,
        "outbound authentik lookups per UserGet RPC must be capped at 128"
    );

    // 4. When one sibling lookup (`trigger_503_user`) fails with 503 while `uncached_frank` succeeds
    // in the same batch (with zero prior local cache hits), `uncached_frank` must still be persisted
    // and returned rather than discarded.
    let partial_fetched = users
        .user_get(bearer_request(
            UserGetRequest {
                partition: ghost_id.into(),
                id: vec!["uncached_frank".to_owned(), "trigger_503_user".to_owned()],
            },
            &alice_token,
        ))
        .await
        .expect("completed sibling fetches must survive a single failing user lookup")
        .into_inner()
        .user;
    assert_eq!(partial_fetched.len(), 1);
    assert_eq!(partial_fetched[0].id, "uncached_frank");
    assert_eq!(
        bridge
            .runtime
            .store
            .find_by_username("uncached_frank")
            .len(),
        1,
        "partially fetched authentik users must be persisted in BridgeStore"
    );
}

#[tokio::test]
async fn restricted_token_grant_for_deleted_project_fails_closed_and_jwks_caches_discovery_url() {
    let idp = MockAuthentik::spawn().await;
    let bridge = RunningBridge::spawn(&idp).await;
    let mut registry = RepositoryRegistryServiceClient::connect(format!("http://{}", bridge.addr))
        .await
        .expect("connect registry");

    let stale_restricted_lead = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-retired-lead",
            "identity": "retired_lead",
            "preferred_username": "retired_lead",
            "name": "Retired Secret Lead",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {
                    "retiredsecret": {
                        "actions": ["read", "write", "admin"],
                        "can_create_repo": true,
                        "visibility": "restricted"
                    }
                }
            }
        }),
    );

    let retired_err = registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: repo_id("54545454545454545454545454545454").into(),
                name: "retiredsecret/prototype".to_owned(),
            },
            &stale_restricted_lead,
        ))
        .await
        .expect_err("deleted restricted project must fail closed with NotFound");
    assert_eq!(retired_err.code(), Code::NotFound);

    assert_eq!(
        idp.cli_discovery_hits.load(Ordering::SeqCst),
        1,
        "initial login token verification fetches OIDC discovery once"
    );

    // Trigger a JWKS key-miss refresh after clearing backoff: `IssuerKeyCache` must reuse the
    // cached `jwks_uri` rather than re-fetching `/.well-known/openid-configuration`.
    bridge.runtime.verifier.clear_refresh_backoff();
    let unknown_kid_token = idp.mint_login_token_with_kid(
        &idp.cli_issuer,
        "rotated-unknown-kid",
        json!({
            "sub": "sub-retired-lead",
            "identity": "retired_lead",
            "preferred_username": "retired_lead",
            "name": "Retired Secret Lead"
        }),
    );
    let _ = registry
        .repository_list(bearer_request(RepositoryListRequest {}, &unknown_kid_token))
        .await;
    assert_eq!(
        idp.cli_discovery_hits.load(Ordering::SeqCst),
        1,
        "JWKS refresh must reuse cached jwks_uri without re-fetching OIDC discovery"
    );
}

#[tokio::test]
async fn tombstoned_deleted_project_tightened_visibility_and_malformed_exchanged_resources_fail_closed()
 {
    let idp = MockAuthentik::spawn().await;
    let bridge = RunningBridge::spawn(&idp).await;
    let http = reqwest::Client::new();
    let mut registry = RepositoryRegistryServiceClient::connect(format!("http://{}", bridge.addr))
        .await
        .expect("connect registry");
    let mut users = UserServiceClient::connect(format!("http://{}", bridge.addr))
        .await
        .expect("connect users");

    let alice_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-alice",
            "identity": "alice",
            "preferred_username": "alice",
            "name": "Alice C-Level",
            "rfs_lore": {
                "is_c_level": true,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": true,
                "global_actions": ["read", "write", "owner", "admin", "migrate", "push-protected", "obliterate", "presign"],
                "projects": {}
            }
        }),
    );
    let secret_lead_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-carla",
            "identity": "carla",
            "preferred_username": "carla",
            "name": "Carla Secret Lead",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {
                    "secretproto": {
                        "actions": ["read", "write", "admin"],
                        "can_create_repo": true,
                        "visibility": "restricted"
                    }
                }
            }
        }),
    );
    let bruno_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-bruno",
            "identity": "bruno",
            "preferred_username": "bruno",
            "name": "Bruno Employee",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {}
            }
        }),
    );

    // 1. Register and unregister `secretproto/one` (leaving a `Restricted` tombstone),
    // delete `secretproto` from authentik, and verify `RepositoryRegister` fails with NotFound.
    let secret_id = repo_id("61616161616161616161616161616161");
    registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: secret_id.into(),
                name: "secretproto/one".to_owned(),
            },
            &secret_lead_token,
        ))
        .await
        .expect("register secretproto/one");
    registry
        .repository_unregister(bearer_request(
            RepositoryUnregisterRequest {
                id: secret_id.into(),
            },
            &secret_lead_token,
        ))
        .await
        .expect("unregister secretproto/one");

    idp.hide_secretproto_group.store(true, Ordering::SeqCst);
    bridge.runtime.verifier.expire_group_cache_ttl();

    let revived_by_lead = registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: repo_id("62626262626262626262626262626262").into(),
                name: "secretproto/revived".to_owned(),
            },
            &secret_lead_token,
        ))
        .await
        .expect_err("deleted project with tombstone must refuse stale lead token");
    assert_eq!(revived_by_lead.code(), Code::NotFound);

    let revived_by_admin = registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: repo_id("63636363636363636363636363636363").into(),
                name: "secretproto/revived-admin".to_owned(),
            },
            &alice_token,
        ))
        .await
        .expect_err("deleted project with tombstone must refuse C-Level registration");
    assert_eq!(revived_by_admin.code(), Code::NotFound);

    // 2. Register `promotable/game` as `Internal`, tighten `promotable` to `Restricted` in authentik,
    // and verify `/token`, `RepositoryList`, and `UserGet` immediately lock out baseline employees.
    let promo_id = repo_id("64646464646464646464646464646464");
    registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: promo_id.into(),
                name: "promotable/game".to_owned(),
            },
            &alice_token,
        ))
        .await
        .expect("register promotable/game");

    let initial_tok = http
        .post(format!("{}/token", bridge.base_url))
        .form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", bruno_token.as_str()),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            (
                "resource",
                &format!("https://lore.roguefairy.net/partitions/{promo_id}"),
            ),
        ])
        .send()
        .await
        .expect("initial employee token exchange");
    assert_eq!(initial_tok.status(), reqwest::StatusCode::OK);

    idp.tighten_promotable_to_restricted
        .store(true, Ordering::SeqCst);
    bridge.runtime.verifier.expire_group_cache_ttl();

    let tightened_tok = http
        .post(format!("{}/token", bridge.base_url))
        .form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", bruno_token.as_str()),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            (
                "resource",
                &format!("https://lore.roguefairy.net/partitions/{promo_id}"),
            ),
        ])
        .send()
        .await
        .expect("tightened employee token exchange");
    assert_eq!(tightened_tok.status(), reqwest::StatusCode::BAD_REQUEST);

    let mut listed_stream = registry
        .repository_list(bearer_request(RepositoryListRequest {}, &bruno_token))
        .await
        .expect("list for bruno after tightening")
        .into_inner();
    assert!(
        listed_stream.next().await.is_none(),
        "tightened project in authentik must disappear from baseline employee RepositoryList"
    );

    let promo_user_err = users
        .user_get(bearer_request(
            UserGetRequest {
                partition: promo_id.into(),
                id: vec!["alice".to_owned()],
            },
            &bruno_token,
        ))
        .await
        .expect_err("tightened project must deny baseline employee UserGet");
    assert_eq!(promo_user_err.code(), Code::PermissionDenied);

    // 3. Exchanged `at+jwt` tokens with empty `resources` or unknown action strings must fail verification.
    let empty_resources_at_jwt = bridge
        .signer
        .sign_access_token(&ExchangedTokenClaims {
            iss: bridge.base_url.clone(),
            sub: "sub-alice".to_owned(),
            identity: "alice".to_owned(),
            aud: vec!["https://lore.roguefairy.net".to_owned()],
            root_domains: vec!["127.0.0.1".to_owned()],
            iat: 1_700_000_000,
            exp: 4_102_444_800,
            preferred_username: "alice".to_owned(),
            name: "Alice".to_owned(),
            is_service_account: false,
            resources: Vec::new(),
        })
        .expect("sign empty-resources at+jwt");
    let empty_res_err = registry
        .repository_list(bearer_request(
            RepositoryListRequest {},
            &empty_resources_at_jwt,
        ))
        .await
        .expect_err("at+jwt with empty resources must fail verification");
    assert_eq!(empty_res_err.code(), Code::Unauthenticated);

    let bad_perm_at_jwt = bridge
        .signer
        .sign_access_token(&ExchangedTokenClaims {
            iss: bridge.base_url.clone(),
            sub: "sub-alice".to_owned(),
            identity: "alice".to_owned(),
            aud: vec!["https://lore.roguefairy.net".to_owned()],
            root_domains: vec!["127.0.0.1".to_owned()],
            iat: 1_700_000_000,
            exp: 4_102_444_800,
            preferred_username: "alice".to_owned(),
            name: "Alice".to_owned(),
            is_service_account: false,
            resources: vec![rfs_lore_bridge::policy::ResourceGrantClaim {
                resource_id: format!("urc-{promo_id}"),
                permission: vec!["not-a-lore-action".to_owned()],
            }],
        })
        .expect("sign bad-permission at+jwt");
    let bad_perm_err = registry
        .repository_list(bearer_request(RepositoryListRequest {}, &bad_perm_at_jwt))
        .await
        .expect_err("at+jwt with unknown action must fail verification");
    assert_eq!(bad_perm_err.code(), Code::Unauthenticated);

    // 4. When the OIDC provider rotates `jwks_uri` to a new endpoint while the old endpoint still serves 200,
    // `IssuerKeyCache` must re-discover `jwks_uri` once the discovery URL TTL has elapsed.
    idp.alternate_jwks_uri.store(true, Ordering::SeqCst);
    bridge
        .runtime
        .verifier
        .backdate_issuer_cache(std::time::Duration::from_secs(301));
    let v2_alice_token = idp.mint_v2_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-alice",
            "identity": "alice",
            "preferred_username": "alice",
            "name": "Alice C-Level",
            "rfs_lore": {
                "is_c_level": true,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": true,
                "global_actions": ["read"],
                "projects": {}
            }
        }),
    );
    let mut v2_listed = registry
        .repository_list(bearer_request(RepositoryListRequest {}, &v2_alice_token))
        .await
        .expect("rotated jwks_uri must succeed after discovery URL TTL")
        .into_inner();
    assert!(
        v2_listed.next().await.is_some(),
        "C-Level token signed by rotated jwks-v2 key must list registered repositories"
    );

    // 5. Custom `PolicyConfig` (`claims_key`, `admin_groups`, `employee_group`, `partner_group`)
    // authorizes tokens carrying organization-specific claim keys and group names without code changes.
    idp.alternate_jwks_uri.store(false, Ordering::SeqCst);
    let custom_policy = rfs_lore_bridge::config::PolicyConfig {
        admin_groups: vec!["Acme Corp - Admins".to_owned()],
        employee_group: "Acme Corp - Staff".to_owned(),
        partner_group: "Acme Corp - Vendors".to_owned(),
        claims_key: "acme_lore".to_owned(),
    };
    let mut custom_cfg = bridge.runtime.config.clone();
    custom_cfg.policy = custom_policy;
    custom_cfg.validate().expect("custom policy config valid");
    let (custom_signer, _) =
        TokenSigner::load_or_generate(None, None).expect("custom policy signer");
    let custom_verifier =
        TokenVerifier::new(custom_cfg, custom_signer).expect("custom policy verifier");
    let acme_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-acme",
            "identity": "acme-admin",
            "preferred_username": "acme-admin",
            "groups": ["Acme Corp - Staff", "Acme Corp - Admins"],
            "acme_lore": {
                "projects": {
                    "ghostlore": {
                        "actions": ["read", "write"],
                        "can_create_repo": true
                    }
                }
            }
        }),
    );
    let verified = custom_verifier
        .verify_any_token(&acme_token)
        .await
        .expect("custom policy token must verify");
    let rfs_lore_bridge::policy::VerifiedCaller::Login(acme_caller) = verified else {
        panic!("expected Login caller");
    };
    assert!(acme_caller.is_c_level);
    assert!(acme_caller.is_employee);
    assert!(!acme_caller.is_partner);
    assert!(acme_caller.can_create_any);
    assert!(acme_caller.projects.contains_key("ghostlore"));
}

#[tokio::test]
async fn register_checks_live_tightening_on_static_project_active_dynamic_idempotency_and_lead_list_outage()
 {
    use rfs_lore_bridge::policy::ProjectVisibility;

    let idp = MockAuthentik::spawn().await;
    let listener = bind_test_listener().await;
    let addr = listener.local_addr().expect("local addr");
    let base_url = format!("http://{addr}");

    let mut projects = BTreeMap::new();
    projects.insert(
        "promotable".to_owned(),
        rfs_lore_bridge::config::StaticProjectConfig {
            visibility: ProjectVisibility::Internal,
            lead_groups: Vec::new(),
            write_groups: Vec::new(),
            read_groups: Vec::new(),
        },
    );
    let config = BridgeConfig {
        bind: addr.to_string(),
        grpc_bind: None,
        issuer: base_url.clone(),
        provider_url: None,
        login_issuers: vec![idp.cli_issuer.clone(), idp.ci_issuer.clone()],
        login_audiences: vec!["https://lore.roguefairy.net".to_owned()],
        audience: "https://lore.roguefairy.net".to_owned(),
        root_domains: vec![
            ".roguefairy.net".to_owned(),
            "127.0.0.1".to_owned(),
            "localhost".to_owned(),
        ],
        resource_prefix: "https://lore.roguefairy.net/partitions/".to_owned(),
        resource_id_template: "urc-{id}".to_owned(),
        token_lifetime_seconds: 300,
        state_path: None,
        user_state_path: None,
        signing_key_path: None,
        signing_key_b64: None,
        authentik: AuthentikApiConfig {
            base_url: Some(idp.base_url.clone()),
            api_token: Some("test-authentik-api-token".to_owned()),
            user_id_field: UserIdField::Username,
        },
        policy: rfs_lore_bridge::config::PolicyConfig::default(),
        projects,
    };
    config.validate().expect("config valid");
    let (signer, _) = TokenSigner::load_or_generate(None, None).expect("signer");
    let verifier = TokenVerifier::new(config.clone(), signer.clone()).expect("verifier");
    let store = BridgeStore::open(None).expect("in-memory store");
    let runtime = Arc::new(BridgeRuntime::new(config, signer, verifier, store));
    let app = build_combined_router(runtime.clone());
    let _server_task = AbortOnDropHandle::new(lore_spawn!(serve_test_router(listener, app)));

    let mut registry = RepositoryRegistryServiceClient::connect(base_url.clone())
        .await
        .expect("connect registry");

    let alice_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-alice",
            "identity": "alice",
            "preferred_username": "alice",
            "name": "Alice C-Level",
            "rfs_lore": {
                "is_c_level": true,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": true,
                "global_actions": ["read"],
                "projects": {}
            }
        }),
    );
    let carla_ghostlore_lead = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-carla",
            "identity": "carla",
            "preferred_username": "carla",
            "name": "Carla GhostLore Lead",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {
                    "ghostlore": {
                        "actions": ["read", "write", "admin"],
                        "can_create_repo": true,
                        "visibility": "internal"
                    }
                }
            }
        }),
    );

    // 1. Static `[projects.promotable] visibility = "internal"` tightened to `restricted` in
    // authentik must latch `Restricted` on `RepositoryRegister`, and fail closed on 503.
    idp.tighten_promotable_to_restricted
        .store(true, Ordering::SeqCst);
    let tightened_id = repo_id("71717171717171717171717171717171");
    registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: tightened_id.into(),
                name: "promotable/tightened-static".to_owned(),
            },
            &alice_token,
        ))
        .await
        .expect("register promotable/tightened-static");
    assert_eq!(
        runtime
            .store
            .get_repository(tightened_id)
            .expect("stored tightened repo")
            .visibility,
        ProjectVisibility::Restricted,
        "RepositoryRegister must consult live authentik tightening even when [projects.<slug>] is Internal"
    );

    // Register `ghostlore/client` (`Internal`) while authentik is healthy.
    let ghost_id = repo_id("72727272727272727272727272727272");
    registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: ghost_id.into(),
                name: "ghostlore/client".to_owned(),
            },
            &carla_ghostlore_lead,
        ))
        .await
        .expect("register ghostlore/client");

    // 2. During an authentik 503 outage (with expired group cache), `RepositoryRegister` on static
    // `Internal` project fails closed with `Unavailable`, whereas `carla_ghostlore_lead`'s
    // `RepositoryList` succeeds because her explicit `write` grant on `ghostlore` does not depend
    // on live project visibility.
    runtime.verifier.expire_group_cache_ttl();
    idp.fail_groups_503.store(true, Ordering::SeqCst);

    let outage_reg = registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: repo_id("73737373737373737373737373737373").into(),
                name: "promotable/outage-check".to_owned(),
            },
            &alice_token,
        ))
        .await
        .expect_err("static Internal project must fail closed on 503 during RepositoryRegister");
    assert_eq!(outage_reg.code(), Code::Unavailable);

    let mut carla_listed = registry
        .repository_list(bearer_request(
            RepositoryListRequest {},
            &carla_ghostlore_lead,
        ))
        .await
        .expect("project lead with explicit write on all Internal repos must succeed during 503")
        .into_inner();
    let first_entry = carla_listed
        .next()
        .await
        .expect("at least one repo")
        .expect("ok entry");
    assert_eq!(hex::encode(&first_entry.id), ghost_id.to_string());
    assert!(carla_listed.next().await.is_none());

    idp.fail_groups_503.store(false, Ordering::SeqCst);

    // 3. Without `[authentik]` Core API (`api_token = None`), a dynamic project created by its
    // project lead allows C-Level idempotent retries (`user.proto`) and subsequent repo creation
    // while active, and rejects revival once all its repositories are unregistered.
    let no_api_listener = bind_test_listener().await;
    let no_api_addr = no_api_listener.local_addr().expect("no-api addr");
    let no_api_url = format!("http://{no_api_addr}");
    let mut no_api_cfg = runtime.config.clone();
    no_api_cfg.bind = no_api_addr.to_string();
    no_api_cfg.issuer = no_api_url.clone();
    no_api_cfg.authentik.api_token = None;
    no_api_cfg.projects.clear();
    no_api_cfg.validate().expect("no-api cfg valid");
    let (no_api_signer, _) = TokenSigner::load_or_generate(None, None).expect("no-api signer");
    let no_api_verifier =
        TokenVerifier::new(no_api_cfg.clone(), no_api_signer.clone()).expect("no-api verifier");
    let no_api_store = BridgeStore::open(None).expect("no-api store");
    let no_api_rt = Arc::new(BridgeRuntime::new(
        no_api_cfg,
        no_api_signer,
        no_api_verifier,
        no_api_store,
    ));
    let _no_api_task = AbortOnDropHandle::new(lore_spawn!(serve_test_router(
        no_api_listener,
        build_combined_router(no_api_rt.clone())
    )));
    let mut no_api_reg = RepositoryRegistryServiceClient::connect(no_api_url)
        .await
        .expect("connect no-api registry");

    let secret_lead = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-secret-lead",
            "identity": "secret-lead",
            "preferred_username": "secret-lead",
            "name": "Secret Lead",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {
                    "secretproto": {
                        "actions": ["read", "write", "admin"],
                        "can_create_repo": true,
                        "visibility": "restricted"
                    }
                }
            }
        }),
    );

    let dyn_id_1 = repo_id("74747474747474747474747474747474");
    let dyn_id_2 = repo_id("75757575757575757575757575757575");
    no_api_reg
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: dyn_id_1.into(),
                name: "secretproto/prototype".to_owned(),
            },
            &secret_lead,
        ))
        .await
        .expect("lead registers secretproto/prototype without authentik API");

    no_api_reg
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: dyn_id_1.into(),
                name: "secretproto/prototype".to_owned(),
            },
            &alice_token,
        ))
        .await
        .expect("C-Level idempotent retry on registered repo must succeed without authentik API");

    no_api_reg
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: dyn_id_2.into(),
                name: "secretproto/tools".to_owned(),
            },
            &alice_token,
        ))
        .await
        .expect(
            "C-Level registration in active dynamic project must succeed without authentik API",
        );
    assert_eq!(
        no_api_rt
            .store
            .get_repository(dyn_id_2)
            .expect("dyn_id_2")
            .visibility,
        ProjectVisibility::Restricted
    );

    no_api_reg
        .repository_unregister(bearer_request(
            RepositoryUnregisterRequest {
                id: dyn_id_1.into(),
            },
            &alice_token,
        ))
        .await
        .expect("unregister dyn_id_1");
    no_api_reg
        .repository_unregister(bearer_request(
            RepositoryUnregisterRequest {
                id: dyn_id_2.into(),
            },
            &alice_token,
        ))
        .await
        .expect("unregister dyn_id_2");

    let revived_without_api = no_api_reg
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: repo_id("76767676767676767676767676767676").into(),
                name: "secretproto/revived".to_owned(),
            },
            &alice_token,
        ))
        .await
        .expect_err("once no active repositories remain, C-Level without API must get NotFound");
    assert_eq!(revived_without_api.code(), Code::NotFound);
}

#[tokio::test]
async fn token_project_visibility_and_null_authentik_fields_behave_fail_closed_and_resiliently() {
    let idp = MockAuthentik::spawn().await;
    let bridge = RunningBridge::spawn(&idp).await;
    let http = reqwest::Client::new();

    let mut registry = RepositoryRegistryServiceClient::connect(bridge.base_url.clone())
        .await
        .expect("connect registry");

    // 1. Register `ghostlore/client` (`Internal`) as `"creator_emp"`. Then present a login token
    // for `"creator_emp"` (`is_employee: true`) carrying `visibility = "restricted"` and
    // `actions = ["read"]` on `ghostlore`. `/token`, `RepositoryList`, and `RepositoryUnregister`
    // must honour the restricted visibility claim immediately.
    let creator_lead = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-creator-emp",
            "identity": "creator_emp",
            "preferred_username": "creator_emp",
            "name": "Creator Employee",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {
                    "ghostlore": {
                        "actions": ["read", "write", "admin"],
                        "can_create_repo": true,
                        "visibility": "internal"
                    }
                }
            }
        }),
    );
    let ghost_id = repo_id("81818181818181818181818181818181");
    registry
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: ghost_id.into(),
                name: "ghostlore/client".to_owned(),
            },
            &creator_lead,
        ))
        .await
        .expect("register ghostlore/client");

    let creator_restricted_read = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-creator-emp",
            "identity": "creator_emp",
            "preferred_username": "creator_emp",
            "name": "Creator Employee",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {
                    "ghostlore": {
                        "actions": ["read"],
                        "can_create_repo": false,
                        "visibility": "restricted"
                    }
                }
            }
        }),
    );

    let exchange_resp = http
        .post(format!("{}/token", bridge.base_url))
        .form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("subject_token", creator_restricted_read.as_str()),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            (
                "resource",
                &format!("https://lore.roguefairy.net/partitions/{ghost_id}"),
            ),
        ])
        .send()
        .await
        .expect("POST /token");
    assert_eq!(exchange_resp.status(), 200);
    let exchange_json: serde_json::Value = exchange_resp.json().await.expect("token json");
    let at_jwt = exchange_json["access_token"]
        .as_str()
        .expect("access_token");
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&["https://lore.roguefairy.net"]);
    validation.set_issuer(std::slice::from_ref(&bridge.base_url));
    let decoded = decode::<ExchangedTokenClaims>(at_jwt, bridge.signer.decoding_key(), &validation)
        .expect("decode exchanged at+jwt");
    assert_eq!(
        decoded.claims.resources[0].permission,
        vec!["read"],
        "POST /token must not grant employee baseline write when token claim marks project restricted"
    );

    let mut listed = registry
        .repository_list(bearer_request(
            RepositoryListRequest {},
            &creator_restricted_read,
        ))
        .await
        .expect("RepositoryList")
        .into_inner();
    let entry = listed
        .next()
        .await
        .expect("listed entry")
        .expect("ok listed entry");
    assert_eq!(
        entry.permission,
        vec!["read"],
        "RepositoryList must honour restricted visibility in token project claim"
    );

    let unreg_err = registry
        .repository_unregister(bearer_request(
            RepositoryUnregisterRequest {
                id: ghost_id.into(),
            },
            &creator_restricted_read,
        ))
        .await
        .expect_err("creator without admin/owner on claim-restricted project must be denied");
    assert_eq!(unreg_err.code(), Code::PermissionDenied);

    // 2. Authentik Core API responses with `"attributes": null`, `"pagination": { "next": null }`,
    // and nullable user fields (`username`, `uuid`, `name`) must deserialize cleanly without 503.
    let null_api_listener = bind_test_listener().await;
    let null_api_addr = null_api_listener.local_addr().expect("null-api addr");
    let null_api_url = format!("http://{null_api_addr}");
    let null_api_app = Router::new()
        .route(
            "/api/v3/core/groups/",
            get(|| async {
                Json(json!({
                    "pagination": { "next": null },
                    "results": [
                        {
                            "name": "Unrelated Null Attributes Group",
                            "attributes": null
                        },
                        {
                            "name": "GhostLore - Leads",
                            "attributes": {
                                "lore_project": "ghostlore",
                                "lore_visibility": "internal",
                                "unrelated_nested": { "blob": [1, 2, 3] }
                            }
                        }
                    ]
                }))
            }),
        )
        .route(
            "/api/v3/core/users/",
            get(|| async {
                Json(json!({
                    "pagination": { "next": null },
                    "results": [
                        {
                            "username": null,
                            "uuid": null,
                            "name": null,
                            "is_active": true
                        },
                        {
                            "username": "nullsafe_author",
                            "uuid": null,
                            "name": null,
                            "is_active": true
                        }
                    ]
                }))
            }),
        );
    let _null_api_task = AbortOnDropHandle::new(lore_spawn!(serve_test_router(
        null_api_listener,
        null_api_app
    )));

    let b2_listener = bind_test_listener().await;
    let b2_addr = b2_listener.local_addr().expect("b2 addr");
    let b2_url = format!("http://{b2_addr}");
    let mut b2_cfg = bridge.runtime.config.clone();
    b2_cfg.bind = b2_addr.to_string();
    b2_cfg.issuer = b2_url.clone();
    b2_cfg.authentik.base_url = Some(null_api_url);
    b2_cfg.policy.claims_key = "acme_lore".to_owned();
    let (b2_signer, _) = TokenSigner::load_or_generate(None, None).expect("b2 signer");
    let b2_verifier = TokenVerifier::new(b2_cfg.clone(), b2_signer.clone()).expect("b2 verifier");
    let b2_store = BridgeStore::open(None).expect("b2 store");
    let b2_rt = Arc::new(BridgeRuntime::new(b2_cfg, b2_signer, b2_verifier, b2_store));
    let _b2_task = AbortOnDropHandle::new(lore_spawn!(serve_test_router(
        b2_listener,
        build_combined_router(b2_rt)
    )));

    let mut b2_reg = RepositoryRegistryServiceClient::connect(b2_url.clone())
        .await
        .expect("connect b2 registry");
    let mut b2_users = UserServiceClient::connect(b2_url)
        .await
        .expect("connect b2 users");

    let expired_custom = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-alice",
            "identity": "alice",
            "preferred_username": "alice",
            "exp": 1_u64,
            "acme_lore": {
                "is_c_level": true,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": true,
                "global_actions": ["read"],
                "projects": {}
            }
        }),
    );
    let expired_err = b2_reg
        .repository_list(bearer_request(RepositoryListRequest {}, &expired_custom))
        .await
        .expect_err("expired custom-claims_key token must fail verification");
    assert_eq!(expired_err.code(), Code::Unauthenticated);

    let valid_custom_c_level = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-alice",
            "identity": "alice",
            "preferred_username": "alice",
            "extra_nested": { "ignored": [true, 42, { "k": "v" }] },
            "acme_lore": {
                "is_c_level": true,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": true,
                "global_actions": ["read"],
                "projects": {}
            }
        }),
    );
    let b2_repo_id = repo_id("82828282828282828282828282828282");
    b2_reg
        .repository_register(bearer_request(
            RepositoryRegisterRequest {
                id: b2_repo_id.into(),
                name: "ghostlore/nullsafe".to_owned(),
            },
            &valid_custom_c_level,
        ))
        .await
        .expect("group lookup must tolerate null attributes and pagination.next = null");

    let user_resp = b2_users
        .user_get(bearer_request(
            UserGetRequest {
                partition: b2_repo_id.into(),
                id: vec!["nullsafe_author".to_owned()],
            },
            &valid_custom_c_level,
        ))
        .await
        .expect("user lookup must tolerate null user fields and pagination.next = null")
        .into_inner();
    assert_eq!(user_resp.user.len(), 1);
    assert_eq!(user_resp.user[0].username, "nullsafe_author");
}

#[tokio::test]
async fn user_find_caps_display_name_pagination_and_rejects_control_char_login_identity() {
    let idp = MockAuthentik::spawn().await;

    let page_hits = Arc::new(AtomicUsize::new(0));
    let page_hits_handler = page_hits.clone();
    let paged_listener = bind_test_listener().await;
    let paged_addr = paged_listener.local_addr().expect("paged user api addr");
    let paged_url = format!("http://{paged_addr}");
    let paged_app = Router::new().route(
        "/api/v3/core/users/",
        get(
            move |AxumQuery(params): AxumQuery<HashMap<String, String>>| {
                let hits = page_hits_handler.clone();
                async move {
                    let n = hits.fetch_add(1, Ordering::SeqCst) + 1;
                    let page: u64 = params.get("page").and_then(|p| p.parse().ok()).unwrap_or(1);
                    Json(json!({
                        "pagination": { "next": page + 1 },
                        "results": [
                            {
                                "username": format!("page_user_{n}"),
                                "uuid": format!("00000000-0000-4000-8000-{n:012x}"),
                                "name": "Different Display Name"
                            }
                        ]
                    }))
                }
            },
        ),
    );
    let _paged_task =
        AbortOnDropHandle::new(lore_spawn!(serve_test_router(paged_listener, paged_app)));

    let b_listener = bind_test_listener().await;
    let b_addr = b_listener.local_addr().expect("bridge addr");
    let b_url = format!("http://{b_addr}");
    let cfg = make_test_bridge_config(
        b_addr.to_string(),
        b_url.clone(),
        vec![idp.cli_issuer.clone(), idp.ci_issuer.clone()],
        Some(paged_url),
        UserIdField::Username,
    );
    let (signer, _) = TokenSigner::load_or_generate(None, None).expect("signer");
    let verifier = TokenVerifier::new(cfg.clone(), signer.clone()).expect("verifier");
    let store = BridgeStore::open(None).expect("store");
    let rt = Arc::new(BridgeRuntime::new(cfg, signer, verifier, store));
    let _b_task = AbortOnDropHandle::new(lore_spawn!(serve_test_router(
        b_listener,
        build_combined_router(rt)
    )));

    let mut reg_client = RepositoryRegistryServiceClient::connect(b_url.clone())
        .await
        .expect("connect registry");
    let mut user_client = UserServiceClient::connect(b_url)
        .await
        .expect("connect users");

    let alice_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-alice",
            "identity": "alice",
            "preferred_username": "alice",
            "rfs_lore": {
                "is_c_level": true,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": true,
                "global_actions": [],
                "projects": {}
            }
        }),
    );
    let find_err = user_client
        .user_find(bearer_request(
            UserFindRequest {
                partition: axum::body::Bytes::new(),
                query: Some(FindQuery::DisplayName("Missing Person".to_owned())),
            },
            &alice_token,
        ))
        .await
        .expect_err("runaway display-name pagination must fail closed as Unavailable");
    assert_eq!(find_err.code(), Code::Unavailable);
    assert_eq!(
        page_hits.load(Ordering::SeqCst),
        5,
        "display-name upstream search must stop after MAX_DISPLAY_NAME_PAGES (5) pages"
    );

    let bad_identity_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-bad",
            "identity": "bad\ninjected",
            "preferred_username": "bad",
            "rfs_lore": {
                "is_c_level": true,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": true,
                "global_actions": [],
                "projects": {}
            }
        }),
    );
    let auth_err = reg_client
        .repository_list(bearer_request(
            RepositoryListRequest {},
            &bad_identity_token,
        ))
        .await
        .expect_err("control characters in login identity must fail authentication");
    assert_eq!(auth_err.code(), Code::Unauthenticated);
}

#[tokio::test]
async fn upstream_user_concurrency_cap_distinct_authentik_origin_and_uuid_reassignment_hold() {
    let idp = MockAuthentik::spawn().await;

    let inflight = Arc::new(AtomicUsize::new(0));
    let peak_inflight = Arc::new(AtomicUsize::new(0));
    let oidc_api_leaks = Arc::new(AtomicUsize::new(0));
    let sam_owner_uuid = Arc::new(parking_lot::RwLock::new(
        "00000000-0000-4000-8000-000000000901".to_owned(),
    ));

    let oidc_listener = bind_test_listener().await;
    let oidc_addr = oidc_listener.local_addr().expect("oidc addr");
    let oidc_url = format!("http://{oidc_addr}");
    let oidc_issuer = idp.cli_issuer.clone();
    let oidc_jwks: serde_json::Value =
        reqwest::get(format!("{}/application/o/rfs-lore-cli/jwks/", idp.base_url))
            .await
            .expect("fetch mock jwks")
            .json()
            .await
            .expect("parse mock jwks");
    let idp_base_for_disc = idp.base_url.clone();
    let leaks_for_oidc = oidc_api_leaks.clone();
    let oidc_app = Router::new()
        .route(
            "/application/o/rfs-lore-cli/.well-known/openid-configuration",
            get(move || {
                let iss = oidc_issuer.clone();
                let idp_base = idp_base_for_disc.clone();
                async move {
                    Json(json!({
                        "issuer": iss,
                        "jwks_uri": format!("{idp_base}/application/o/rfs-lore-cli/jwks/")
                    }))
                }
            }),
        )
        .route(
            "/application/o/rfs-lore-cli/jwks/",
            get(move || {
                let jwks = oidc_jwks.clone();
                async move { Json(jwks) }
            }),
        )
        .route(
            "/api/v3/core/users/",
            get(move || {
                let leaks = leaks_for_oidc.clone();
                async move {
                    leaks.fetch_add(1, Ordering::SeqCst);
                    axum::http::StatusCode::FORBIDDEN
                }
            }),
        );
    let _oidc_task =
        AbortOnDropHandle::new(lore_spawn!(serve_test_router(oidc_listener, oidc_app)));

    let api_listener = bind_test_listener().await;
    let api_addr = api_listener.local_addr().expect("api addr");
    let api_url = format!("http://{api_addr}");
    let inflight_route = inflight.clone();
    let peak_route = peak_inflight.clone();
    let sam_owner_route = sam_owner_uuid.clone();
    let api_app = Router::new().route(
        "/api/v3/core/users/",
        get(
            move |AxumQuery(params): AxumQuery<HashMap<String, String>>| {
                let cur = inflight_route.clone();
                let peak = peak_route.clone();
                let sam_owner = sam_owner_route.clone();
                async move {
                    let active = cur.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(active, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    cur.fetch_sub(1, Ordering::SeqCst);

                    if params.get("username").map(String::as_str) == Some("reassigned_sam") {
                        let owner = sam_owner.read().clone();
                        return Json(json!({
                            "pagination": { "next": 0 },
                            "results": [{
                                "username": "reassigned_sam",
                                "uuid": owner,
                                "name": "Sam Reassigned"
                            }]
                        }));
                    }
                    if let Some(uid) = params.get("uuid") {
                        return Json(json!({
                            "pagination": { "next": 0 },
                            "results": [{
                                "username": format!("u_{}", &uid[24..]),
                                "uuid": uid,
                                "name": format!("User {}", &uid[24..])
                            }]
                        }));
                    }
                    if let Some(uname) = params.get("username") {
                        return Json(json!({
                            "pagination": { "next": 0 },
                            "results": [{
                                "username": uname,
                                "uuid": format!("00000000-0000-4000-8000-{:012x}", uname.len()),
                                "name": format!("Display {uname}")
                            }]
                        }));
                    }
                    Json(json!({ "pagination": { "next": 0 }, "results": [] }))
                }
            },
        ),
    );
    let _api_task = AbortOnDropHandle::new(lore_spawn!(serve_test_router(api_listener, api_app)));

    let b_listener = bind_test_listener().await;
    let b_addr = b_listener.local_addr().expect("b addr");
    let b_url = format!("http://{b_addr}");
    let mut cfg = make_test_bridge_config(
        b_addr.to_string(),
        b_url.clone(),
        vec![idp.cli_issuer.clone(), idp.ci_issuer.clone()],
        Some(api_url),
        UserIdField::Uuid,
    );
    cfg.provider_url = Some(oidc_url);
    let (signer, _) = TokenSigner::load_or_generate(None, None).expect("signer");
    let verifier = TokenVerifier::new(cfg.clone(), signer.clone()).expect("verifier");
    let store = BridgeStore::open_with_user_id_field(None, UserIdField::Uuid).expect("store");
    let rt = Arc::new(BridgeRuntime::new(cfg, signer, verifier, store));
    let _b_task = AbortOnDropHandle::new(lore_spawn!(serve_test_router(
        b_listener,
        build_combined_router(rt)
    )));

    let alice_uuid = "9a7b2c1d-0000-4000-8000-0000000000aa";
    let alice_token = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-alice",
            "identity": alice_uuid,
            "preferred_username": "alice",
            "rfs_lore": {
                "is_c_level": true,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": true,
                "global_actions": [],
                "projects": {}
            }
        }),
    );

    let channel = tonic::transport::Endpoint::from_shared(b_url.clone())
        .expect("endpoint")
        .connect()
        .await
        .expect("connect");

    let mut tasks = tokio::task::JoinSet::new();
    for batch_idx in 0..3_u32 {
        let mut client = UserServiceClient::new(channel.clone());
        let tok = alice_token.clone();
        let ids: Vec<String> = (0..6_u32)
            .map(|i| format!("00000000-0000-4000-8000-{:012x}", 100 + batch_idx * 10 + i))
            .collect();
        lore_spawn!(tasks, async move {
            client
                .user_get(bearer_request(
                    UserGetRequest {
                        partition: axum::body::Bytes::new(),
                        id: ids,
                    },
                    &tok,
                ))
                .await
                .expect("concurrent user_get");
        });
    }
    for find_idx in 0..4_u32 {
        let mut client = UserServiceClient::new(channel.clone());
        let tok = alice_token.clone();
        let uname = format!("concurrent_finder_{find_idx}_x");
        lore_spawn!(tasks, async move {
            client
                .user_find(bearer_request(
                    UserFindRequest {
                        partition: axum::body::Bytes::new(),
                        query: Some(FindQuery::Username(uname)),
                    },
                    &tok,
                ))
                .await
                .expect("concurrent user_find");
        });
    }
    while let Some(res) = tasks.join_next().await {
        res.expect("join concurrent user lookup task");
    }

    assert_eq!(
        oidc_api_leaks.load(Ordering::SeqCst),
        0,
        "Core API bearer requests must hit authentik.base_url and never leak to provider_url"
    );
    let observed_peak = peak_inflight.load(Ordering::SeqCst);
    assert!(
        observed_peak <= 8,
        "process-wide upstream user directory concurrency ({observed_peak}) must never exceed MAX_FALLBACK_CONCURRENCY (8)"
    );

    // Verify UUID username reassignment via live caller authentication (`RepositoryList`).
    let mut reg_client = RepositoryRegistryServiceClient::new(channel.clone());
    let mut user_client = UserServiceClient::new(channel);
    let uuid_old = "00000000-0000-4000-8000-000000000901";
    let uuid_new = "00000000-0000-4000-8000-000000000902";

    let sam_old_tok = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-sam-old",
            "identity": uuid_old,
            "preferred_username": "reassigned_sam",
            "name": "Sam Old",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {}
            }
        }),
    );
    reg_client
        .repository_list(bearer_request(RepositoryListRequest {}, &sam_old_tok))
        .await
        .expect("sam old repository_list");

    *sam_owner_uuid.write() = uuid_new.to_owned();
    let sam_new_tok = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-sam-new",
            "identity": uuid_new,
            "preferred_username": "reassigned_sam",
            "name": "Sam Reassigned",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {}
            }
        }),
    );
    reg_client
        .repository_list(bearer_request(RepositoryListRequest {}, &sam_new_tok))
        .await
        .expect("sam new repository_list");

    let found_sam = user_client
        .user_find(bearer_request(
            UserFindRequest {
                partition: axum::body::Bytes::new(),
                query: Some(FindQuery::Username("reassigned_sam".to_owned())),
            },
            &alice_token,
        ))
        .await
        .expect("find reassigned_sam")
        .into_inner();
    assert_eq!(found_sam.user.len(), 1);
    assert_eq!(
        found_sam.user[0].id, uuid_new,
        "reassigned username must resolve to the new UUID rather than staying wedged on the old UUID"
    );
    assert_eq!(found_sam.user[0].username, "reassigned_sam");
}

#[tokio::test]
async fn uuid_conflict_resolution_protects_existing_owner_when_confirmed_or_on_outage_and_cooldown()
{
    let idp = MockAuthentik::spawn().await;
    let fail_lookup = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let fail_route = fail_lookup.clone();
    let uuid_a = "00000000-0000-4000-8000-000000000801";
    let uuid_b = "00000000-0000-4000-8000-000000000802";
    let uuid_c = "00000000-0000-4000-8000-000000000803";

    let api_listener = bind_test_listener().await;
    let api_addr = api_listener.local_addr().expect("api addr");
    let api_url = format!("http://{api_addr}");
    let api_app = Router::new().route(
        "/api/v3/core/users/",
        get(
            move |AxumQuery(params): AxumQuery<HashMap<String, String>>| {
                let should_fail = fail_route.load(Ordering::SeqCst);
                async move {
                    if should_fail {
                        return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
                    }
                    if params.get("username").map(String::as_str) == Some("carla_protected") {
                        return Json(json!({
                            "pagination": { "next": 0 },
                            "results": [{
                                "username": "carla_protected",
                                "uuid": uuid_a,
                                "name": "Carla True Owner"
                            }]
                        }))
                        .into_response();
                    }
                    Json(json!({ "pagination": { "next": 0 }, "results": [] })).into_response()
                }
            },
        ),
    );
    let _api_task = AbortOnDropHandle::new(lore_spawn!(serve_test_router(api_listener, api_app)));

    let b_listener = bind_test_listener().await;
    let b_addr = b_listener.local_addr().expect("b addr");
    let b_url = format!("http://{b_addr}");
    let cfg = make_test_bridge_config(
        b_addr.to_string(),
        b_url.clone(),
        vec![idp.cli_issuer.clone(), idp.ci_issuer.clone()],
        Some(api_url),
        UserIdField::Uuid,
    );
    let (signer, _) = TokenSigner::load_or_generate(None, None).expect("signer");
    let verifier = TokenVerifier::new(cfg.clone(), signer.clone()).expect("verifier");
    let store = BridgeStore::open_with_user_id_field(None, UserIdField::Uuid).expect("store");
    let rt = Arc::new(BridgeRuntime::new(cfg, signer, verifier, store));
    let _b_task = AbortOnDropHandle::new(lore_spawn!(serve_test_router(
        b_listener,
        build_combined_router(rt.clone())
    )));

    let channel = tonic::transport::Endpoint::from_shared(b_url)
        .expect("endpoint")
        .connect()
        .await
        .expect("connect");
    let mut reg_client = RepositoryRegistryServiceClient::new(channel.clone());
    let mut user_client = UserServiceClient::new(channel);

    let tok_a = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-a",
            "iat": 1000,
            "identity": uuid_a,
            "preferred_username": "carla_protected",
            "name": "Carla True Owner",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {}
            }
        }),
    );
    reg_client
        .repository_list(bearer_request(RepositoryListRequest {}, &tok_a))
        .await
        .expect("tok_a repository_list");

    // During an `authentik` 503 outage AND on an immediate second call hitting the 10s cooldown,
    // `uuid_b` with newer `iat = 1500` must NOT steal `carla_protected` from `uuid_a`.
    let tok_b = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-b",
            "iat": 1500,
            "identity": uuid_b,
            "preferred_username": "carla_protected",
            "name": "Impostor B",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {}
            }
        }),
    );
    reg_client
        .repository_list(bearer_request(RepositoryListRequest {}, &tok_b))
        .await
        .expect("tok_b first repository_list");
    reg_client
        .repository_list(bearer_request(RepositoryListRequest {}, &tok_b))
        .await
        .expect("tok_b cooldown repository_list");

    let after_outage = user_client
        .user_find(bearer_request(
            UserFindRequest {
                partition: axum::body::Bytes::new(),
                query: Some(FindQuery::Username("carla_protected".to_owned())),
            },
            &tok_a,
        ))
        .await
        .expect("find carla_protected after outage")
        .into_inner();
    assert_eq!(after_outage.user.len(), 1);
    assert_eq!(
        after_outage.user[0].id, uuid_a,
        "unconfirmed OIDC caller must not take over conflicting username during authentik 503 or cooldown"
    );

    // Once `authentik` recovers and confirms `uuid_a` still owns `carla_protected`, `uuid_c` with
    // `iat = 2000` must also fail to displace `uuid_a`.
    fail_lookup.store(false, Ordering::SeqCst);
    let tok_c = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-c",
            "iat": 2000,
            "identity": uuid_c,
            "preferred_username": "carla_protected",
            "name": "Impostor C",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {}
            }
        }),
    );
    reg_client
        .repository_list(bearer_request(RepositoryListRequest {}, &tok_c))
        .await
        .expect("tok_c repository_list");

    let after_confirm = user_client
        .user_find(bearer_request(
            UserFindRequest {
                partition: axum::body::Bytes::new(),
                query: Some(FindQuery::Username("carla_protected".to_owned())),
            },
            &tok_a,
        ))
        .await
        .expect("find carla_protected after confirm")
        .into_inner();
    assert_eq!(after_confirm.user.len(), 1);
    assert_eq!(
        after_confirm.user[0].id, uuid_a,
        "authentik-confirmed UUID owner must retain username against newer OIDC iat"
    );
}

#[tokio::test]
async fn discovery_rejects_trailing_slash_issuer_mismatch_and_missing_kid_returns_missing_key_id() {
    let idp = MockAuthentik::spawn().await;
    let oidc_jwks: serde_json::Value =
        reqwest::get(format!("{}/application/o/rfs-lore-cli/jwks/", idp.base_url))
            .await
            .expect("fetch mock jwks")
            .json()
            .await
            .expect("parse mock jwks");

    let disc_listener = bind_test_listener().await;
    let disc_addr = disc_listener.local_addr().expect("disc addr");
    let configured_no_slash = format!("http://{disc_addr}");
    let discovery_with_slash = format!("http://{disc_addr}/");
    let jwks_url = format!("http://{disc_addr}/jwks");
    let disc_iss = discovery_with_slash.clone();
    let disc_jwks_uri = jwks_url.clone();
    let disc_app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(move || {
                let iss = disc_iss.clone();
                let uri = disc_jwks_uri.clone();
                async move {
                    Json(json!({
                        "issuer": iss,
                        "jwks_uri": uri,
                    }))
                }
            }),
        )
        .route(
            "/jwks",
            get(move || {
                let jwks = oidc_jwks.clone();
                async move { Json(jwks) }
            }),
        );
    let _disc_task =
        AbortOnDropHandle::new(lore_spawn!(serve_test_router(disc_listener, disc_app)));

    let cfg = make_test_bridge_config(
        "127.0.0.1:8190".to_owned(),
        "https://lore-auth.roguefairy.net".to_owned(),
        vec![configured_no_slash.clone()],
        None,
        UserIdField::Username,
    );
    let (signer, _) = TokenSigner::load_or_generate(None, None).expect("signer");
    let verifier = TokenVerifier::new(cfg, signer).expect("verifier");

    let token_no_slash = idp.mint_login_token(
        &configured_no_slash,
        json!({
            "sub": "sub-alice",
            "preferred_username": "alice",
            "rfs_lore": {
                "is_c_level": true,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": true,
                "global_actions": [],
                "projects": {}
            }
        }),
    );
    let mismatch_err = verifier
        .verify_login_token(&token_no_slash)
        .await
        .expect_err("discovery issuer with trailing slash must not match configured issuer without trailing slash");
    assert!(
        matches!(
            mismatch_err,
            rfs_lore_bridge::error::AuthVerifyError::ProviderUnavailable { .. }
        ),
        "expected ProviderUnavailable on OIDC discovery exact-issuer mismatch, got {mismatch_err:?}"
    );

    let no_kid_header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
    let empty_payload = URL_SAFE_NO_PAD.encode(b"{}");
    let no_kid_jwt = format!("{no_kid_header}.{empty_payload}.sig");
    let missing_kid_err = verifier
        .verify_login_token(&no_kid_jwt)
        .await
        .expect_err("JWT missing kid must fail before payload JSON probing");
    assert!(
        matches!(
            missing_kid_err,
            rfs_lore_bridge::error::AuthVerifyError::MissingKeyId
        ),
        "expected MissingKeyId before untrusted payload decode, got {missing_kid_err:?}"
    );
}

#[test]
fn boxed_cold_paths_keep_hot_verification_and_caller_profile_futures_small() {
    use std::mem::size_of;
    use std::mem::size_of_val;

    let cfg = make_test_bridge_config(
        "127.0.0.1:8190".to_owned(),
        "https://lore-auth.roguefairy.net".to_owned(),
        vec!["https://auth.roguefairy.net/application/o/rfs-lore-cli/".to_owned()],
        Some("https://auth.roguefairy.net".to_owned()),
        UserIdField::Uuid,
    );
    let (signer, _) = TokenSigner::load_or_generate(None, None).expect("signer");
    let verifier = TokenVerifier::new(cfg.clone(), signer.clone()).expect("verifier");
    let store = BridgeStore::open_with_user_id_field(None, UserIdField::Uuid).expect("store");
    let runtime = BridgeRuntime::new(cfg, signer, verifier, store);
    let verifier = &runtime.verifier;

    let parts = rfs_lore_bridge::jwks::split_jwt("a.b.c").expect("split a.b.c");
    let slow_fut = verifier.verify_login_token_slow(
        &parts,
        jsonwebtoken::Algorithm::ES256,
        String::new(),
        String::new(),
        None,
    );
    let login_fut = verifier.verify_login_token("a.b.c");
    let any_fut = verifier.verify_any_token("a.b.c");

    assert!(
        size_of_val(&slow_fut) < size_of::<rfs_lore_bridge::jwks::StackJwtPayloadBuf>(),
        "verify_login_token_slow holds {} bytes across await, must not hold StackJwtPayloadBuf ({})",
        size_of_val(&slow_fut),
        size_of::<rfs_lore_bridge::jwks::StackJwtPayloadBuf>()
    );
    assert!(
        size_of_val(&login_fut) < size_of_val(&slow_fut),
        "verify_login_token holds {} bytes, verify_login_token_slow holds {}",
        size_of_val(&login_fut),
        size_of_val(&slow_fut)
    );
    assert!(
        size_of_val(&any_fut) < size_of_val(&slow_fut),
        "verify_any_token holds {} bytes, verify_login_token_slow holds {}",
        size_of_val(&any_fut),
        size_of_val(&slow_fut)
    );

    let caller = rfs_lore_bridge::policy::CallerClaims {
        sub: String::new(),
        identity: String::new(),
        username: String::new(),
        display_name: String::new(),
        is_service_account: false,
        token_iat: None,
        exp: 0,
        is_c_level: false,
        is_employee: false,
        is_partner: false,
        can_create_any: false,
        global_actions: rfs_lore_bridge::policy::ActionSet::EMPTY,
        projects: std::collections::BTreeMap::new(),
    };
    let record_fut = runtime.record_caller_profile(&caller);
    let conflict_fut = runtime.resolve_uuid_username_conflict("id", "username");
    assert!(
        size_of_val(&record_fut) < size_of_val(&conflict_fut),
        "record_caller_profile holds {} bytes, resolve_uuid_username_conflict holds {}",
        size_of_val(&record_fut),
        size_of_val(&conflict_fut)
    );
}

#[tokio::test]
async fn uuid_first_claim_unconfirmed_username_verifies_against_authentik_on_user_find_and_ignores_invalid_group_slugs()
 {
    let idp = MockAuthentik::spawn().await;
    let uuid_old = "00000000-0000-4000-8000-000000000961";
    let uuid_new = "00000000-0000-4000-8000-000000000962";
    let uuid_ghost = "00000000-0000-4000-8000-000000000963";

    let api_listener = bind_test_listener().await;
    let api_addr = api_listener.local_addr().expect("api addr");
    let api_url = format!("http://{api_addr}");
    let api_app = Router::new()
        .route(
            "/api/v3/core/users/",
            get(
                move |AxumQuery(params): AxumQuery<HashMap<String, String>>| async move {
                    if params.get("username").map(String::as_str) == Some("squatted_sam") {
                        return Json(json!({
                            "pagination": { "next": 0 },
                            "results": [{
                                "username": "squatted_sam",
                                "uuid": uuid_new,
                                "name": "Sam Authoritative"
                            }]
                        }));
                    }
                    Json(json!({ "pagination": { "next": 0 }, "results": [] }))
                },
            ),
        )
        .route(
            "/api/v3/core/groups/",
            get(|| async {
                Json(json!({
                    "pagination": { "next": 0 },
                    "results": [
                        {
                            "name": "Malformed Slug Group",
                            "attributes": {
                                "lore_project": "Invalid Upper / Space Slug!",
                                "lore_visibility": "restricted"
                            }
                        },
                        {
                            "name": "Oversized Slug Group",
                            "attributes": {
                                "lore_project": "a".repeat(65),
                                "lore_visibility": "restricted"
                            }
                        },
                        {
                            "name": "GhostLore Group",
                            "attributes": {
                                "lore_project": "ghostlore",
                                "lore_visibility": "internal"
                            }
                        }
                    ]
                }))
            }),
        );
    let _api_task = AbortOnDropHandle::new(lore_spawn!(serve_test_router(api_listener, api_app)));

    let b_listener = bind_test_listener().await;
    let b_addr = b_listener.local_addr().expect("bridge addr");
    let b_url = format!("http://{b_addr}");
    let cfg = make_test_bridge_config(
        b_addr.to_string(),
        b_url.clone(),
        vec![idp.cli_issuer.clone(), idp.ci_issuer.clone()],
        Some(api_url),
        UserIdField::Uuid,
    );
    let (signer, _) = TokenSigner::load_or_generate(None, None).expect("signer");
    let verifier = TokenVerifier::new(cfg.clone(), signer.clone()).expect("verifier");
    let store = BridgeStore::open_with_user_id_field(None, UserIdField::Uuid).expect("store");
    let rt = Arc::new(BridgeRuntime::new(cfg, signer, verifier, store));
    let _b_task = AbortOnDropHandle::new(lore_spawn!(serve_test_router(
        b_listener,
        build_combined_router(rt.clone())
    )));

    let mut reg_client = RepositoryRegistryServiceClient::connect(b_url.clone())
        .await
        .expect("connect registry");
    let mut user_client = UserServiceClient::connect(b_url)
        .await
        .expect("connect users");

    // 1. `uuid_old` calls the bridge first with an unconfirmed OIDC claim for `squatted_sam`.
    let tok_old = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-old",
            "iat": 1000,
            "identity": uuid_old,
            "preferred_username": "squatted_sam",
            "name": "Old Sam",
            "rfs_lore": {
                "is_c_level": true,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": true,
                "global_actions": [],
                "projects": {}
            }
        }),
    );
    reg_client
        .repository_list(bearer_request(RepositoryListRequest {}, &tok_old))
        .await
        .expect("tok_old repository_list");

    // `UserFind(Username("squatted_sam"))` must consult `authentik` for the unconfirmed entry,
    // return `uuid_new`, and evict `squatted_sam` from `uuid_old`.
    let found_sam = user_client
        .user_find(bearer_request(
            UserFindRequest {
                partition: axum::body::Bytes::new(),
                query: Some(FindQuery::Username("squatted_sam".to_owned())),
            },
            &tok_old,
        ))
        .await
        .expect("find squatted_sam")
        .into_inner();
    assert_eq!(found_sam.user.len(), 1);
    assert_eq!(
        found_sam.user[0].id, uuid_new,
        "unconfirmed first-claim username must verify against authentik on UserFind"
    );

    // 2. `uuid_ghost` claims `vanished_name`, which `authentik` reports no longer exists (`[]`).
    let tok_ghost = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-ghost",
            "iat": 1000,
            "identity": uuid_ghost,
            "preferred_username": "vanished_name",
            "name": "Ghost Caller",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {}
            }
        }),
    );
    reg_client
        .repository_list(bearer_request(RepositoryListRequest {}, &tok_ghost))
        .await
        .expect("tok_ghost repository_list");

    let found_vanished = user_client
        .user_find(bearer_request(
            UserFindRequest {
                partition: axum::body::Bytes::new(),
                query: Some(FindQuery::Username("vanished_name".to_owned())),
            },
            &tok_old,
        ))
        .await
        .expect("find vanished_name")
        .into_inner();
    assert!(
        found_vanished.user.is_empty(),
        "unconfirmed username absent from authentik must be cleared and return empty"
    );

    // Also verify `UserGet` 100%-cache-hit path preserves caller-supplied raw UUID casing and cleared usernames.
    let upper_new = uuid_new.to_ascii_uppercase();
    let batch_got = user_client
        .user_get(bearer_request(
            UserGetRequest {
                partition: axum::body::Bytes::new(),
                id: vec![
                    uuid_old.to_owned(),
                    upper_new.clone(),
                    uuid_ghost.to_owned(),
                ],
            },
            &tok_old,
        ))
        .await
        .expect("batch user_get")
        .into_inner();
    assert_eq!(batch_got.user.len(), 3);
    assert_eq!(batch_got.user[0].id, uuid_old);
    assert_eq!(batch_got.user[0].username, "");
    assert_eq!(batch_got.user[1].id, upper_new);
    assert_eq!(batch_got.user[1].username, "squatted_sam");
    assert_eq!(batch_got.user[2].id, uuid_ghost);
    assert_eq!(batch_got.user[2].username, "");

    // 3. Group visibility refresh must ignore invalid/oversized `lore_project` values.
    let ghost_vis = rt
        .verifier
        .lookup_authentik_project_visibility("ghostlore")
        .await;
    assert_eq!(
        ghost_vis,
        rfs_lore_bridge::jwks::AuthentikProjectLookup::Found(
            rfs_lore_bridge::policy::ProjectVisibility::Internal
        )
    );
    assert_eq!(
        rt.verifier.cached_project_visibility_count(),
        1,
        "only valid project slugs may be stored in GroupVisibilityCache"
    );
}

#[tokio::test]
async fn uuid_negative_cache_bypass_preserves_newly_created_oidc_user() {
    let idp = MockAuthentik::spawn().await;
    let uuid_admin = "00000000-0000-4000-8000-000000000971";
    let uuid_new_hire = "00000000-0000-4000-8000-000000000972";

    let enable_new_hire = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let enable_new_hire_srv = enable_new_hire.clone();

    let api_listener = bind_test_listener().await;
    let api_addr = api_listener.local_addr().expect("api addr");
    let api_url = format!("http://{api_addr}");
    let api_app = Router::new()
        .route(
            "/api/v3/core/users/",
            get(
                move |AxumQuery(params): AxumQuery<HashMap<String, String>>| {
                    let new_hire_live = enable_new_hire_srv.load(Ordering::SeqCst);
                    async move {
                        if new_hire_live
                            && (params.get("username").map(String::as_str) == Some("new_hire")
                                || params.get("uuid").map(String::as_str) == Some(uuid_new_hire))
                        {
                            return Json(json!({
                                "pagination": { "next": 0 },
                                "results": [{
                                    "username": "new_hire",
                                    "uuid": uuid_new_hire,
                                    "name": "New Hire"
                                }]
                            }));
                        }
                        Json(json!({ "pagination": { "next": 0 }, "results": [] }))
                    }
                },
            ),
        )
        .route(
            "/api/v3/core/groups/",
            get(|| async { Json(json!({ "pagination": { "next": 0 }, "results": [] })) }),
        );
    let _api_task = AbortOnDropHandle::new(lore_spawn!(serve_test_router(api_listener, api_app)));

    let b_listener = bind_test_listener().await;
    let b_addr = b_listener.local_addr().expect("bridge addr");
    let b_url = format!("http://{b_addr}");
    let cfg = make_test_bridge_config(
        b_addr.to_string(),
        b_url.clone(),
        vec![idp.cli_issuer.clone(), idp.ci_issuer.clone()],
        Some(api_url),
        UserIdField::Uuid,
    );
    let (signer, _) = TokenSigner::load_or_generate(None, None).expect("signer");
    let verifier = TokenVerifier::new(cfg.clone(), signer.clone()).expect("verifier");
    let store = BridgeStore::open_with_user_id_field(None, UserIdField::Uuid).expect("store");
    let rt = Arc::new(BridgeRuntime::new(cfg, signer, verifier, store));
    let _b_task = AbortOnDropHandle::new(lore_spawn!(serve_test_router(
        b_listener,
        build_combined_router(rt)
    )));

    let mut reg_client = RepositoryRegistryServiceClient::connect(b_url.clone())
        .await
        .expect("connect registry");
    let mut user_client = UserServiceClient::connect(b_url)
        .await
        .expect("connect users");

    let tok_admin = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-admin",
            "iat": 1000,
            "identity": uuid_admin,
            "preferred_username": "admin_op",
            "name": "Admin Op",
            "rfs_lore": {
                "is_c_level": true,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": true,
                "global_actions": [],
                "projects": {}
            }
        }),
    );

    let miss_find = user_client
        .user_find(bearer_request(
            UserFindRequest {
                partition: axum::body::Bytes::new(),
                query: Some(FindQuery::Username("new_hire".to_owned())),
            },
            &tok_admin,
        ))
        .await
        .expect("initial miss find")
        .into_inner();
    assert!(miss_find.user.is_empty());

    let miss_get = user_client
        .user_get(bearer_request(
            UserGetRequest {
                partition: axum::body::Bytes::new(),
                id: vec![uuid_new_hire.to_owned()],
            },
            &tok_admin,
        ))
        .await
        .expect("initial miss get")
        .into_inner();
    assert!(miss_get.user.is_empty());

    enable_new_hire.store(true, Ordering::SeqCst);
    let tok_new_hire = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-new-hire",
            "iat": 1000,
            "identity": uuid_new_hire,
            "preferred_username": "new_hire",
            "name": "New Hire",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {}
            }
        }),
    );
    reg_client
        .repository_list(bearer_request(RepositoryListRequest {}, &tok_new_hire))
        .await
        .expect("new_hire repository_list");

    let found_new_hire = user_client
        .user_find(bearer_request(
            UserFindRequest {
                partition: axum::body::Bytes::new(),
                query: Some(FindQuery::Username("new_hire".to_owned())),
            },
            &tok_admin,
        ))
        .await
        .expect("find new_hire after login")
        .into_inner();
    assert_eq!(
        found_new_hire.user.len(),
        1,
        "stale negative cache must not wipe a newly created OIDC-verified user on UserFind"
    );
    assert_eq!(found_new_hire.user[0].id, uuid_new_hire);
    assert_eq!(found_new_hire.user[0].username, "new_hire");
}

#[tokio::test]
async fn uuid_refuted_username_watermark_suppresses_stale_token_resurrection() {
    let idp = MockAuthentik::spawn().await;
    let uuid_admin = "00000000-0000-4000-8000-000000000981";
    let uuid_ghost = "00000000-0000-4000-8000-000000000983";
    let uuid_stale_a = "00000000-0000-4000-8000-000000000984";
    let uuid_stale_b = "00000000-0000-4000-8000-000000000985";

    let enable_vanished_reassigned = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let enable_vanished_srv = enable_vanished_reassigned.clone();

    let api_listener = bind_test_listener().await;
    let api_addr = api_listener.local_addr().expect("api addr");
    let api_url = format!("http://{api_addr}");
    let api_app = Router::new()
        .route(
            "/api/v3/core/users/",
            get(
                move |AxumQuery(params): AxumQuery<HashMap<String, String>>| {
                    let vanished_live = enable_vanished_srv.load(Ordering::SeqCst);
                    async move {
                        if vanished_live
                            && params.get("username").map(String::as_str) == Some("vanished_name")
                        {
                            return Json(json!({
                                "pagination": { "next": 0 },
                                "results": [{
                                    "username": "vanished_name",
                                    "uuid": uuid_ghost,
                                    "name": "Ghost Reassigned"
                                }]
                            }));
                        }
                        Json(json!({ "pagination": { "next": 0 }, "results": [] }))
                    }
                },
            ),
        )
        .route(
            "/api/v3/core/groups/",
            get(|| async { Json(json!({ "pagination": { "next": 0 }, "results": [] })) }),
        );
    let _api_task = AbortOnDropHandle::new(lore_spawn!(serve_test_router(api_listener, api_app)));

    let dir = lore_base::test_util::TempDir::new("uuid-refuted-watermark-");
    let repos_path = dir.child("repos.json");
    let users_path = dir.child("users.json");

    let b_listener = bind_test_listener().await;
    let b_addr = b_listener.local_addr().expect("bridge addr");
    let b_url = format!("http://{b_addr}");
    let cfg = make_test_bridge_config(
        b_addr.to_string(),
        b_url.clone(),
        vec![idp.cli_issuer.clone(), idp.ci_issuer.clone()],
        Some(api_url),
        UserIdField::Uuid,
    );
    let (signer, _) = TokenSigner::load_or_generate(None, None).expect("signer");
    let verifier = TokenVerifier::new(cfg.clone(), signer.clone()).expect("verifier");
    let store = BridgeStore::open_with_paths_and_field(
        Some(repos_path),
        Some(users_path.clone()),
        UserIdField::Uuid,
    )
    .expect("store");
    let rt = Arc::new(BridgeRuntime::new(cfg, signer, verifier, store));
    let _b_task = AbortOnDropHandle::new(lore_spawn!(serve_test_router(
        b_listener,
        build_combined_router(rt)
    )));

    let mut reg_client = RepositoryRegistryServiceClient::connect(b_url.clone())
        .await
        .expect("connect registry");
    let mut user_client = UserServiceClient::connect(b_url)
        .await
        .expect("connect users");

    let tok_admin = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-admin",
            "iat": 1000,
            "identity": uuid_admin,
            "preferred_username": "admin_op",
            "name": "Admin Op",
            "rfs_lore": {
                "is_c_level": true,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": true,
                "global_actions": [],
                "projects": {}
            }
        }),
    );

    let tok_ghost = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-ghost",
            "iat": 1000,
            "identity": uuid_ghost,
            "preferred_username": "vanished_name",
            "name": "Ghost Caller",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {}
            }
        }),
    );
    let first_vanished = user_client
        .user_find(bearer_request(
            UserFindRequest {
                partition: axum::body::Bytes::new(),
                query: Some(FindQuery::Username("vanished_name".to_owned())),
            },
            &tok_ghost,
        ))
        .await
        .expect("tok_ghost find vanished_name")
        .into_inner();
    assert!(first_vanished.user.is_empty());

    reg_client
        .repository_list(bearer_request(RepositoryListRequest {}, &tok_ghost))
        .await
        .expect("tok_ghost subsequent repository_list");

    let got_ghost = user_client
        .user_get(bearer_request(
            UserGetRequest {
                partition: axum::body::Bytes::new(),
                id: vec![uuid_ghost.to_owned()],
            },
            &tok_admin,
        ))
        .await
        .expect("get uuid_ghost")
        .into_inner();
    assert_eq!(got_ghost.user.len(), 1);
    assert_eq!(
        got_ghost.user[0].username, "",
        "subsequent RPC with same unexpired token must not resurrect a directory-refuted username"
    );

    let persisted_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&users_path).expect("read users.json"))
            .expect("parse users.json");
    let ghost_persisted = persisted_json["users"]
        .as_array()
        .expect("users array")
        .iter()
        .find(|u| u["id"].as_str() == Some(uuid_ghost))
        .expect("uuid_ghost persisted");
    assert_eq!(ghost_persisted["username"].as_str(), Some(""));

    let tok_stale_a = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-stale-a",
            "iat": 900,
            "identity": uuid_stale_a,
            "preferred_username": "retired_alias",
            "name": "Stale A",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {}
            }
        }),
    );
    let tok_stale_b = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-stale-b",
            "iat": 950,
            "identity": uuid_stale_b,
            "preferred_username": "retired_alias",
            "name": "Stale B",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {}
            }
        }),
    );
    reg_client
        .repository_list(bearer_request(RepositoryListRequest {}, &tok_stale_a))
        .await
        .expect("stale_a list 1");
    reg_client
        .repository_list(bearer_request(RepositoryListRequest {}, &tok_stale_b))
        .await
        .expect("stale_b conflict list 1");
    reg_client
        .repository_list(bearer_request(RepositoryListRequest {}, &tok_stale_a))
        .await
        .expect("stale_a list 2");
    reg_client
        .repository_list(bearer_request(RepositoryListRequest {}, &tok_stale_b))
        .await
        .expect("stale_b list 2");

    let got_stale = user_client
        .user_get(bearer_request(
            UserGetRequest {
                partition: axum::body::Bytes::new(),
                id: vec![uuid_stale_a.to_owned(), uuid_stale_b.to_owned()],
            },
            &tok_admin,
        ))
        .await
        .expect("get stale pair")
        .into_inner();
    assert_eq!(got_stale.user.len(), 2);
    assert_eq!(got_stale.user[0].username, "");
    assert_eq!(got_stale.user[1].username, "");

    enable_vanished_reassigned.store(true, Ordering::SeqCst);
    let tok_ghost_reassigned = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-ghost",
            "iat": 2000,
            "identity": uuid_ghost,
            "preferred_username": "vanished_name",
            "name": "Ghost Reassigned",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {}
            }
        }),
    );
    reg_client
        .repository_list(bearer_request(
            RepositoryListRequest {},
            &tok_ghost_reassigned,
        ))
        .await
        .expect("ghost reassigned list");

    let found_reassigned = user_client
        .user_find(bearer_request(
            UserFindRequest {
                partition: axum::body::Bytes::new(),
                query: Some(FindQuery::Username("vanished_name".to_owned())),
            },
            &tok_admin,
        ))
        .await
        .expect("find reassigned vanished_name")
        .into_inner();
    assert_eq!(found_reassigned.user.len(), 1);
    assert_eq!(found_reassigned.user[0].id, uuid_ghost);
    assert_eq!(found_reassigned.user[0].username, "vanished_name");
}

#[tokio::test]
async fn uuid_stale_token_preserves_confirmed_and_newer_username_across_restarts_and_renames() {
    let idp = MockAuthentik::spawn().await;
    let uuid_admin = "9a7b2c1d-0000-4000-8000-00000000f100";
    let uuid_carla = "9a7b2c1d-0000-4000-8000-00000000f101";
    let uuid_dev = "9a7b2c1d-0000-4000-8000-00000000f102";
    let uuid_vanished = "9a7b2c1d-0000-4000-8000-00000000f103";

    let carla_live_username = Arc::new(parking_lot::RwLock::new("new_carla".to_owned()));
    let carla_live_for_api = carla_live_username.clone();

    let api_listener = bind_test_listener().await;
    let api_addr = api_listener.local_addr().expect("api addr");
    let api_url = format!("http://{api_addr}");
    let api_app = Router::new()
        .route(
            "/api/v3/core/users/",
            get(
                move |AxumQuery(params): AxumQuery<HashMap<String, String>>| {
                    let current_carla = carla_live_for_api.read().clone();
                    async move {
                        let query_username = params.get("username").map(String::as_str);
                        let query_uuid = params.get("uuid").map(String::as_str);
                        if query_username == Some(current_carla.as_str())
                            || query_uuid == Some(uuid_carla)
                        {
                            return Json(json!({
                                "pagination": { "next": 0 },
                                "results": [{
                                    "username": current_carla,
                                    "uuid": uuid_carla,
                                    "name": "Carla Lead"
                                }]
                            }));
                        }
                        Json(json!({ "pagination": { "next": 0 }, "results": [] }))
                    }
                },
            ),
        )
        .route(
            "/api/v3/core/groups/",
            get(|| async { Json(json!({ "pagination": { "next": 0 }, "results": [] })) }),
        );
    let _api_task = AbortOnDropHandle::new(lore_spawn!(serve_test_router(api_listener, api_app)));

    let dir = lore_base::test_util::TempDir::new("uuid-monotonic-profile-");
    let repos_path = dir.child("repos.json");
    let users_path = dir.child("users.json");

    let tok_admin = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-admin",
            "iat": 1000,
            "identity": uuid_admin,
            "preferred_username": "admin_op",
            "name": "Admin Op",
            "rfs_lore": {
                "is_c_level": true,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": true,
                "global_actions": [],
                "projects": {}
            }
        }),
    );
    let tok_carla_old = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-carla",
            "iat": 1000,
            "identity": uuid_carla,
            "preferred_username": "old_carla",
            "name": "Carla Old",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {}
            }
        }),
    );
    let tok_vanished = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-vanished",
            "iat": 1000,
            "identity": uuid_vanished,
            "preferred_username": "vanished_old",
            "name": "Vanished User",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {}
            }
        }),
    );

    {
        let b_listener = bind_test_listener().await;
        let b_addr = b_listener.local_addr().expect("bridge addr");
        let b_url = format!("http://{b_addr}");
        let cfg = make_test_bridge_config(
            b_addr.to_string(),
            b_url.clone(),
            vec![idp.cli_issuer.clone(), idp.ci_issuer.clone()],
            Some(api_url.clone()),
            UserIdField::Uuid,
        );
        let (signer, _) = TokenSigner::load_or_generate(None, None).expect("signer");
        let verifier = TokenVerifier::new(cfg.clone(), signer.clone()).expect("verifier");
        let store = BridgeStore::open_with_paths_and_field(
            Some(repos_path.clone()),
            Some(users_path.clone()),
            UserIdField::Uuid,
        )
        .expect("store");
        let rt = Arc::new(BridgeRuntime::new(cfg, signer, verifier, store));
        let _b_task = AbortOnDropHandle::new(lore_spawn!(serve_test_router(
            b_listener,
            build_combined_router(rt)
        )));

        let mut reg_client = RepositoryRegistryServiceClient::connect(b_url.clone())
            .await
            .expect("connect registry");
        let mut user_client = UserServiceClient::connect(b_url)
            .await
            .expect("connect users");

        // 1. `uuid_carla` authenticates with pre-rename `tok_carla_old` (`old_carla`, iat=1000),
        //    `UserFind("old_carla")` refutes `old_carla`, then `UserFind("new_carla")` confirms
        //    `uuid_carla` as `new_carla` (`u64::MAX`). A subsequent RPC with `tok_carla_old`
        //    must NOT wipe `new_carla`.
        let refuted_old = user_client
            .user_find(bearer_request(
                UserFindRequest {
                    partition: axum::body::Bytes::new(),
                    query: Some(FindQuery::Username("old_carla".to_owned())),
                },
                &tok_carla_old,
            ))
            .await
            .expect("refute old_carla")
            .into_inner();
        assert!(refuted_old.user.is_empty());

        let confirmed_new = user_client
            .user_find(bearer_request(
                UserFindRequest {
                    partition: axum::body::Bytes::new(),
                    query: Some(FindQuery::Username("new_carla".to_owned())),
                },
                &tok_admin,
            ))
            .await
            .expect("confirm new_carla")
            .into_inner();
        assert_eq!(confirmed_new.user.len(), 1);
        assert_eq!(confirmed_new.user[0].id, uuid_carla);

        reg_client
            .repository_list(bearer_request(RepositoryListRequest {}, &tok_carla_old))
            .await
            .expect("list with stale tok_carla_old");

        let got_carla = user_client
            .user_get(bearer_request(
                UserGetRequest {
                    partition: axum::body::Bytes::new(),
                    id: vec![uuid_carla.to_owned()],
                },
                &tok_admin,
            ))
            .await
            .expect("get uuid_carla after stale token")
            .into_inner();
        assert_eq!(got_carla.user.len(), 1);
        assert_eq!(
            got_carla.user[0].username, "new_carla",
            "stale refuted OIDC token must not wipe directory-confirmed username"
        );

        // 2. Alternating finite-iat OIDC tokens for `uuid_dev` must keep the newer iat=2000 profile.
        let tok_dev_v2 = idp.mint_login_token(
            &idp.cli_issuer,
            json!({
                "sub": "sub-dev",
                "iat": 2000,
                "identity": uuid_dev,
                "preferred_username": "dev_v2",
                "name": "Dev V2",
                "rfs_lore": {
                    "is_c_level": false,
                    "is_employee": true,
                    "is_partner": false,
                    "can_create_any": false,
                    "global_actions": [],
                    "projects": {}
                }
            }),
        );
        let tok_dev_v1 = idp.mint_login_token(
            &idp.cli_issuer,
            json!({
                "sub": "sub-dev",
                "iat": 1500,
                "identity": uuid_dev,
                "preferred_username": "dev_v1",
                "name": "Dev V1",
                "rfs_lore": {
                    "is_c_level": false,
                    "is_employee": true,
                    "is_partner": false,
                    "can_create_any": false,
                    "global_actions": [],
                    "projects": {}
                }
            }),
        );
        reg_client
            .repository_list(bearer_request(RepositoryListRequest {}, &tok_dev_v2))
            .await
            .expect("dev v2 list");
        reg_client
            .repository_list(bearer_request(RepositoryListRequest {}, &tok_dev_v1))
            .await
            .expect("dev v1 list");

        let got_dev = user_client
            .user_get(bearer_request(
                UserGetRequest {
                    partition: axum::body::Bytes::new(),
                    id: vec![uuid_dev.to_owned()],
                },
                &tok_admin,
            ))
            .await
            .expect("get uuid_dev")
            .into_inner();
        assert_eq!(got_dev.user.len(), 1);
        assert_eq!(
            got_dev.user[0].username, "dev_v2",
            "older finite-iat OIDC token must not roll back a newer OIDC username for the same UUID"
        );

        // 3. Seed and refute `vanished_old` before restarting the bridge.
        let refuted_vanished = user_client
            .user_find(bearer_request(
                UserFindRequest {
                    partition: axum::body::Bytes::new(),
                    query: Some(FindQuery::Username("vanished_old".to_owned())),
                },
                &tok_vanished,
            ))
            .await
            .expect("refute vanished_old")
            .into_inner();
        assert!(refuted_vanished.user.is_empty());
    }

    // Reopen from disk: persisted `refuted_iat` must prevent `tok_vanished` from resurrecting
    // `vanished_old`, and a genuine post-confirmation rename of `uuid_carla` to `carla_v3`
    // must update `uuid_carla` on live check.
    let b_listener = bind_test_listener().await;
    let b_addr = b_listener.local_addr().expect("reopened bridge addr");
    let b_url = format!("http://{b_addr}");
    let cfg = make_test_bridge_config(
        b_addr.to_string(),
        b_url.clone(),
        vec![idp.cli_issuer.clone(), idp.ci_issuer.clone()],
        Some(api_url),
        UserIdField::Uuid,
    );
    let (signer, _) = TokenSigner::load_or_generate(None, None).expect("signer");
    let verifier = TokenVerifier::new(cfg.clone(), signer.clone()).expect("verifier");
    let store = BridgeStore::open_with_paths_and_field(
        Some(repos_path),
        Some(users_path),
        UserIdField::Uuid,
    )
    .expect("reopen store");
    let rt = Arc::new(BridgeRuntime::new(cfg, signer, verifier, store));
    let _b_task = AbortOnDropHandle::new(lore_spawn!(serve_test_router(
        b_listener,
        build_combined_router(rt)
    )));

    let mut reg_client = RepositoryRegistryServiceClient::connect(b_url.clone())
        .await
        .expect("connect reopened registry");
    let mut user_client = UserServiceClient::connect(b_url)
        .await
        .expect("connect reopened users");

    reg_client
        .repository_list(bearer_request(RepositoryListRequest {}, &tok_vanished))
        .await
        .expect("list with tok_vanished after restart");
    let got_vanished = user_client
        .user_get(bearer_request(
            UserGetRequest {
                partition: axum::body::Bytes::new(),
                id: vec![uuid_vanished.to_owned()],
            },
            &tok_admin,
        ))
        .await
        .expect("get uuid_vanished after restart")
        .into_inner();
    assert_eq!(
        got_vanished.user[0].username, "",
        "persisted refuted_iat watermark must suppress stale token resurrection across restart"
    );

    *carla_live_username.write() = "carla_v3".to_owned();
    let tok_carla_v3 = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-carla",
            "iat": 3000,
            "identity": uuid_carla,
            "preferred_username": "carla_v3",
            "name": "Carla Lead",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {}
            }
        }),
    );
    reg_client
        .repository_list(bearer_request(RepositoryListRequest {}, &tok_carla_v3))
        .await
        .expect("list with post-rename tok_carla_v3");
    let found_v3 = user_client
        .user_find(bearer_request(
            UserFindRequest {
                partition: axum::body::Bytes::new(),
                query: Some(FindQuery::Username("carla_v3".to_owned())),
            },
            &tok_admin,
        ))
        .await
        .expect("find carla_v3")
        .into_inner();
    assert_eq!(found_v3.user.len(), 1);
    assert_eq!(found_v3.user[0].id, uuid_carla);
    assert_eq!(found_v3.user[0].username, "carla_v3");
}

#[tokio::test]
async fn uuid_concurrent_user_find_miss_preserves_interleaved_login_profile() {
    let idp = MockAuthentik::spawn().await;
    let uuid_admin = "9a7b2c1d-0000-4000-8000-00000000f200";
    let uuid_new_hire = "9a7b2c1d-0000-4000-8000-00000000f201";

    let lookup_park: JwksParkSlot = Arc::new(parking_lot::Mutex::new(None));
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    *lookup_park.lock() = Some((entered_tx, release_rx));
    let lookup_park_for_api = lookup_park.clone();

    let api_listener = bind_test_listener().await;
    let api_addr = api_listener.local_addr().expect("api addr");
    let api_url = format!("http://{api_addr}");
    let api_app = Router::new()
        .route(
            "/api/v3/core/users/",
            get(
                move |AxumQuery(params): AxumQuery<HashMap<String, String>>| {
                    let park = lookup_park_for_api.clone();
                    async move {
                        if params.get("username").map(String::as_str) == Some("new_hire") {
                            let maybe_park = park.lock().take();
                            if let Some((tx, rx)) = maybe_park {
                                let _ = tx.send(());
                                let _ = rx.await;
                            }
                        }
                        Json(json!({ "pagination": { "next": 0 }, "results": [] }))
                    }
                },
            ),
        )
        .route(
            "/api/v3/core/groups/",
            get(|| async { Json(json!({ "pagination": { "next": 0 }, "results": [] })) }),
        );
    let _api_task = AbortOnDropHandle::new(lore_spawn!(serve_test_router(api_listener, api_app)));

    let b_listener = bind_test_listener().await;
    let b_addr = b_listener.local_addr().expect("bridge addr");
    let b_url = format!("http://{b_addr}");
    let cfg = make_test_bridge_config(
        b_addr.to_string(),
        b_url.clone(),
        vec![idp.cli_issuer.clone(), idp.ci_issuer.clone()],
        Some(api_url),
        UserIdField::Uuid,
    );
    let (signer, _) = TokenSigner::load_or_generate(None, None).expect("signer");
    let verifier = TokenVerifier::new(cfg.clone(), signer.clone()).expect("verifier");
    let store = BridgeStore::open_with_user_id_field(None, UserIdField::Uuid).expect("store");
    let rt = Arc::new(BridgeRuntime::new(cfg, signer, verifier, store));
    let _b_task = AbortOnDropHandle::new(lore_spawn!(serve_test_router(
        b_listener,
        build_combined_router(rt)
    )));

    let mut reg_client = RepositoryRegistryServiceClient::connect(b_url.clone())
        .await
        .expect("connect registry");
    let mut user_client = UserServiceClient::connect(b_url.clone())
        .await
        .expect("connect users");
    let mut bg_user_client = UserServiceClient::connect(b_url)
        .await
        .expect("connect bg users");

    let tok_admin = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-admin",
            "iat": 1000,
            "identity": uuid_admin,
            "preferred_username": "admin_op",
            "name": "Admin Op",
            "rfs_lore": {
                "is_c_level": true,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": true,
                "global_actions": [],
                "projects": {}
            }
        }),
    );
    let tok_new_hire = idp.mint_login_token(
        &idp.cli_issuer,
        json!({
            "sub": "sub-new-hire",
            "iat": 2000,
            "identity": uuid_new_hire,
            "preferred_username": "new_hire",
            "name": "New Hire",
            "rfs_lore": {
                "is_c_level": false,
                "is_employee": true,
                "is_partner": false,
                "can_create_any": false,
                "global_actions": [],
                "projects": {}
            }
        }),
    );

    let tok_admin_bg = tok_admin.clone();
    let in_flight_find = lore_spawn!(async move {
        bg_user_client
            .user_find(bearer_request(
                UserFindRequest {
                    partition: axum::body::Bytes::new(),
                    query: Some(FindQuery::Username("new_hire".to_owned())),
                },
                &tok_admin_bg,
            ))
            .await
    });

    entered_rx.await.expect("UserFind entered live lookup");

    // While `UserFind("new_hire")` (which started with no local owner) is in flight,
    // `new_hire` logs in and records `uuid_new_hire -> "new_hire"` at `iat = 2000`.
    reg_client
        .repository_list(bearer_request(RepositoryListRequest {}, &tok_new_hire))
        .await
        .expect("new_hire concurrent login");

    let _ = release_tx.send(());
    let find_resp = in_flight_find
        .await
        .expect("join UserFind")
        .expect("UserFind response")
        .into_inner();
    assert!(find_resp.user.is_empty());

    // The pre-login miss must NOT clear or refute `uuid_new_hire`'s interleaved login profile.
    let got_hire = user_client
        .user_get(bearer_request(
            UserGetRequest {
                partition: axum::body::Bytes::new(),
                id: vec![uuid_new_hire.to_owned()],
            },
            &tok_admin,
        ))
        .await
        .expect("UserGet uuid_new_hire")
        .into_inner();
    assert_eq!(got_hire.user.len(), 1);
    assert_eq!(
        got_hire.user[0].username, "new_hire",
        "in-flight UserFind started before login must not clear or refute interleaved OIDC login"
    );
}

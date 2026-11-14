// SPDX-FileCopyrightText: 2026 Rogue Fairy Studios
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::path::Path;

use lore_base::test_util::TempFile;
use rfs_lore_bridge::config::BridgeConfig;
use rfs_lore_bridge::config::UserIdField;
use rfs_lore_bridge::error::ConfigError;
use rfs_lore_bridge::policy::ProjectVisibility;

const MINIMAL_VALID_TOML: &str = r#"
issuer = "https://lore-auth.roguefairy.net/"
login_issuers = ["https://auth.telluriancorp.info/application/o/rfs-lore-cli/"]
audience = "https://lore.roguefairy.net"
resource_prefix = "https://lore.roguefairy.net/partitions/"
"#;

#[test]
fn minimal_toml_normalizes_issuer_and_defaults_login_audiences() {
    let cfg = BridgeConfig::from_toml_str(MINIMAL_VALID_TOML).expect("valid TOML");
    assert_eq!(cfg.issuer, "https://lore-auth.roguefairy.net");
    assert_eq!(cfg.login_audiences, vec!["https://lore.roguefairy.net"]);
    assert_eq!(cfg.resource_id_template, "urc-{id}");
    assert_eq!(cfg.token_lifetime_seconds, 300);
}

#[test]
fn env_overrides_and_railway_port_apply() {
    let file = TempFile::with_contents("bridge-cfg-", MINIMAL_VALID_TOML.as_bytes());
    let mut env = HashMap::new();
    env.insert("PORT".to_owned(), "9123".to_owned());
    env.insert(
        "RFS_LORE_ROOT_DOMAINS".to_owned(),
        ".roguefairy.net, localhost".to_owned(),
    );
    env.insert(
        "RFS_LORE_AUTHENTIK_API_TOKEN".to_owned(),
        "secret-token".to_owned(),
    );

    let cfg = BridgeConfig::load(Some(file.path()), |k| env.get(k).cloned()).expect("load config");
    assert_eq!(cfg.bind, "0.0.0.0:9123");
    assert_eq!(cfg.root_domains, vec![".roguefairy.net", "localhost"]);
    assert_eq!(cfg.authentik.api_token.as_deref(), Some("secret-token"));
}

#[test]
fn shipped_bridge_configs_parse_without_error() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let parent = manifest_dir.parent().expect("roguefairy dir");

    let prod = BridgeConfig::load(Some(&parent.join("bridge.example.toml")), |_| None)
        .expect("bridge.example.toml must parse");
    assert_eq!(
        prod.projects["ghostlore"].visibility,
        ProjectVisibility::Internal
    );

    let prod_railway = BridgeConfig::load(Some(&parent.join("bridge.example.toml")), |k| {
        (k == "PORT").then(|| "4321".to_owned())
    })
    .expect("bridge.example.toml with Railway PORT");
    assert_eq!(
        prod_railway.bind, "0.0.0.0:4321",
        "bridge.example.toml must let Railway PORT apply when RFS_LORE_BIND is unset"
    );

    let local = BridgeConfig::load(Some(&parent.join("bridge-local.toml")), |_| None)
        .expect("bridge-local.toml must parse");
    assert_eq!(
        local.projects["secretproto"].visibility,
        ProjectVisibility::Restricted
    );
}

#[test]
fn validation_rejects_invalid_fields_by_variant() {
    let bad_template = format!("{MINIMAL_VALID_TOML}\nresource_id_template = \"urc-static\"\n");
    assert!(matches!(
        BridgeConfig::from_toml_str(&bad_template),
        Err(ConfigError::MissingIdPlaceholder { .. })
    ));

    let bad_ttl = format!("{MINIMAL_VALID_TOML}\ntoken_lifetime_seconds = 7200\n");
    assert!(matches!(
        BridgeConfig::from_toml_str(&bad_ttl),
        Err(ConfigError::InvalidTokenLifetime { seconds: 7200 })
    ));

    let bad_slug =
        format!("{MINIMAL_VALID_TOML}\n[projects.GhostLore]\nvisibility = \"internal\"\n");
    assert!(matches!(
        BridgeConfig::from_toml_str(&bad_slug),
        Err(ConfigError::InvalidProjectSlug { .. })
    ));

    let bad_url = r#"
issuer = "ftp://lore-auth.roguefairy.net"
login_issuers = ["https://auth.telluriancorp.info/application/o/rfs-lore-cli/"]
audience = "https://lore.roguefairy.net"
resource_prefix = "https://lore.roguefairy.net/partitions/"
"#;
    assert!(matches!(
        BridgeConfig::from_toml_str(bad_url),
        Err(ConfigError::InvalidUrl {
            field: "issuer",
            ..
        })
    ));

    let file = TempFile::with_contents("bridge-cfg-bad-ttl-", MINIMAL_VALID_TOML.as_bytes());
    let mut env = HashMap::new();
    env.insert(
        "RFS_LORE_TOKEN_LIFETIME_SECONDS".to_owned(),
        "not-a-number".to_owned(),
    );
    assert!(matches!(
        BridgeConfig::load(Some(file.path()), |k| env.get(k).cloned()),
        Err(ConfigError::InvalidTokenLifetimeEnv { .. })
    ));

    let bad_uid_field = format!("{MINIMAL_VALID_TOML}\n[authentik]\nuser_id_field = \"uid\"\n");
    assert!(matches!(
        BridgeConfig::from_toml_str(&bad_uid_field),
        Err(ConfigError::InvalidUserIdField { .. })
    ));

    let uuid_field = format!("{MINIMAL_VALID_TOML}\n[authentik]\nuser_id_field = \"uuid\"\n");
    let parsed_uuid = BridgeConfig::from_toml_str(&uuid_field).expect("uuid user_id_field");
    assert_eq!(parsed_uuid.authentik.user_id_field, UserIdField::Uuid);

    let self_login_issuer = r#"
issuer = "https://lore-auth.roguefairy.net/"
login_issuers = ["https://lore-auth.roguefairy.net"]
audience = "https://lore.roguefairy.net"
resource_prefix = "https://lore.roguefairy.net/partitions/"
"#;
    assert!(
        matches!(
            BridgeConfig::from_toml_str(self_login_issuer),
            Err(ConfigError::SelfLoginIssuer { .. })
        ),
        "login_issuers containing Bridge's own issuer must return SelfLoginIssuer"
    );
}

#[test]
fn debug_output_redacts_signing_key_and_api_token() {
    let file = TempFile::with_contents("bridge-cfg-redact-", MINIMAL_VALID_TOML.as_bytes());
    let mut env = HashMap::new();
    env.insert(
        "RFS_LORE_SIGNING_KEY_B64".to_owned(),
        "SUPER_SECRET_PRIVATE_KEY_MATERIAL".to_owned(),
    );
    env.insert(
        "RFS_LORE_AUTHENTIK_API_TOKEN".to_owned(),
        "SUPER_SECRET_AUTHENTIK_TOKEN".to_owned(),
    );

    let cfg = BridgeConfig::load(Some(file.path()), |k| env.get(k).cloned()).expect("load config");
    let rendered = format!("{cfg:?}");
    assert!(
        !rendered.contains("SUPER_SECRET_PRIVATE_KEY_MATERIAL"),
        "BridgeConfig Debug leaked signing_key_b64: {rendered}"
    );
    assert!(
        !rendered.contains("SUPER_SECRET_AUTHENTIK_TOKEN"),
        "BridgeConfig Debug leaked authentik.api_token: {rendered}"
    );
}

#[test]
fn env_trimming_duplicate_bind_and_api_token_validation() {
    let file = TempFile::with_contents("bridge-cfg-trim-", MINIMAL_VALID_TOML.as_bytes());
    let mut env = HashMap::new();
    env.insert("PORT".to_owned(), "9123\n".to_owned());
    env.insert(
        "RFS_LORE_ISSUER".to_owned(),
        "https://lore-auth.roguefairy.net/\r\n".to_owned(),
    );
    env.insert(
        "RFS_LORE_AUTHENTIK_USER_ID_FIELD".to_owned(),
        "uuid\n".to_owned(),
    );
    env.insert(
        "RFS_LORE_AUTHENTIK_API_TOKEN".to_owned(),
        "secret-token\n".to_owned(),
    );

    let cfg = BridgeConfig::load(Some(file.path()), |k| env.get(k).cloned())
        .expect("trailing newlines in env vars must be trimmed");
    assert_eq!(cfg.bind, "0.0.0.0:9123");
    assert_eq!(cfg.issuer, "https://lore-auth.roguefairy.net");
    assert_eq!(cfg.authentik.user_id_field, UserIdField::Uuid);
    assert_eq!(cfg.authentik.api_token.as_deref(), Some("secret-token"));

    let dup_bind_toml = format!(
        "{MINIMAL_VALID_TOML}\nbind = \"127.0.0.1:8190\"\ngrpc_bind = \"127.0.0.1:8190\"\n"
    );
    assert!(
        matches!(
            BridgeConfig::from_toml_str(&dup_bind_toml),
            Err(ConfigError::DuplicateBindAddress { .. })
        ),
        "identical bind and grpc_bind addresses must return DuplicateBindAddress"
    );

    let mut bad_token_env = HashMap::new();
    bad_token_env.insert(
        "RFS_LORE_AUTHENTIK_API_TOKEN".to_owned(),
        "bad\x07token".to_owned(),
    );
    assert!(
        matches!(
            BridgeConfig::load(Some(file.path()), |k| bad_token_env.get(k).cloned()),
            Err(ConfigError::InvalidApiToken)
        ),
        "control characters in RFS_LORE_AUTHENTIK_API_TOKEN must return InvalidApiToken"
    );
}

#[test]
fn toml_trimming_dual_stack_bind_conflict_and_space_in_api_token() {
    let dual_stack_toml =
        format!("{MINIMAL_VALID_TOML}\nbind = \"0.0.0.0:8190\"\ngrpc_bind = \"[::]:8190\"\n");
    assert!(
        matches!(
            BridgeConfig::from_toml_str(&dual_stack_toml),
            Err(ConfigError::DuplicateBindAddress { .. })
        ),
        "0.0.0.0:8190 and [::]:8190 conflict on dual-stack hosts"
    );

    let mapped_v6_toml = format!(
        "{MINIMAL_VALID_TOML}\nbind = \"127.0.0.1:8190\"\ngrpc_bind = \"[::ffff:127.0.0.1]:8190\"\n"
    );
    assert!(
        matches!(
            BridgeConfig::from_toml_str(&mapped_v6_toml),
            Err(ConfigError::DuplicateBindAddress { .. })
        ),
        "IPv4-mapped IPv6 address conflicts with matching IPv4 socket"
    );

    let padded_toml = r#"
bind = " 127.0.0.1:8190 "
grpc_bind = " 127.0.0.1:8191 "
issuer = " https://lore-auth.roguefairy.net/ "
login_issuers = [" https://auth.telluriancorp.info/application/o/rfs-lore-cli/ "]
audience = " https://lore.roguefairy.net "
root_domains = [" .roguefairy.net "]
resource_prefix = " https://lore.roguefairy.net/partitions/ "
resource_id_template = " urc-{id} "

[authentik]
base_url = " https://auth.telluriancorp.info "
user_id_field = " uuid "
"#;
    let padded_cfg = BridgeConfig::from_toml_str(padded_toml)
        .expect("padded TOML string fields must be trimmed");
    assert_eq!(padded_cfg.bind, "127.0.0.1:8190");
    assert_eq!(padded_cfg.grpc_bind.as_deref(), Some("127.0.0.1:8191"));
    assert_eq!(padded_cfg.issuer, "https://lore-auth.roguefairy.net");
    assert_eq!(padded_cfg.audience, "https://lore.roguefairy.net");
    assert_eq!(padded_cfg.root_domains, vec![".roguefairy.net"]);
    assert_eq!(
        padded_cfg.resource_prefix,
        "https://lore.roguefairy.net/partitions/"
    );
    assert_eq!(padded_cfg.resource_id_template, "urc-{id}");
    assert_eq!(padded_cfg.authentik.user_id_field, UserIdField::Uuid);

    let blank_root_domain_toml =
        format!("{MINIMAL_VALID_TOML}\nroot_domains = [\".roguefairy.net\", \"   \"]\n");
    assert!(
        matches!(
            BridgeConfig::from_toml_str(&blank_root_domain_toml),
            Err(ConfigError::EmptyField {
                field: "root_domains"
            })
        ),
        "blank entry in root_domains must fail validation"
    );

    let file = TempFile::with_contents("bridge-cfg-space-tok-", MINIMAL_VALID_TOML.as_bytes());
    let mut bearer_prefix_env = HashMap::new();
    bearer_prefix_env.insert(
        "RFS_LORE_AUTHENTIK_API_TOKEN".to_owned(),
        "Bearer secret-token".to_owned(),
    );
    assert!(
        matches!(
            BridgeConfig::load(Some(file.path()), |k| bearer_prefix_env.get(k).cloned()),
            Err(ConfigError::InvalidApiToken)
        ),
        "internal whitespace in RFS_LORE_AUTHENTIK_API_TOKEN must return InvalidApiToken"
    );
}

#[test]
fn blank_toml_paths_normalize_to_none_and_policy_env_overrides_apply() {
    let blank_paths_toml = format!(
        "{MINIMAL_VALID_TOML}\nstate_path = \"   \"\nuser_state_path = \"\"\nsigning_key_path = \" \\t \"\n"
    );
    let parsed = BridgeConfig::from_toml_str(&blank_paths_toml)
        .expect("blank path strings in TOML must normalize to None");
    assert!(parsed.state_path.is_none());
    assert!(parsed.user_state_path.is_none());
    assert!(parsed.signing_key_path.is_none());

    let file = TempFile::with_contents("bridge-cfg-policy-env-", MINIMAL_VALID_TOML.as_bytes());
    let mut env = HashMap::new();
    env.insert(
        "RFS_LORE_POLICY_ADMIN_GROUPS".to_owned(),
        "Ops Admins, Studio Chiefs".to_owned(),
    );
    env.insert(
        "RFS_LORE_POLICY_EMPLOYEE_GROUP".to_owned(),
        "Studio Staff".to_owned(),
    );
    env.insert(
        "RFS_LORE_POLICY_PARTNER_GROUP".to_owned(),
        "External Vendors".to_owned(),
    );
    env.insert(
        "RFS_LORE_POLICY_CLAIMS_KEY".to_owned(),
        "studio_lore".to_owned(),
    );
    let cfg = BridgeConfig::load(Some(file.path()), |k| env.get(k).cloned())
        .expect("policy env overrides must load");
    assert_eq!(cfg.policy.admin_groups, vec!["Ops Admins", "Studio Chiefs"]);
    assert_eq!(cfg.policy.employee_group, "Studio Staff");
    assert_eq!(cfg.policy.partner_group, "External Vendors");
    assert_eq!(cfg.policy.claims_key, "studio_lore");
}

#[test]
fn root_domains_defaults_from_endpoints_and_rejects_uncovered_issuer_or_audience() {
    let cfg = BridgeConfig::from_toml_str(MINIMAL_VALID_TOML).expect("minimal valid TOML");
    assert_eq!(
        cfg.root_domains,
        vec![
            "lore-auth.roguefairy.net".to_owned(),
            "lore.roguefairy.net".to_owned(),
        ]
    );

    let mixed_case = format!("{MINIMAL_VALID_TOML}\nroot_domains = [\".RogueFairy.NET\"]\n");
    let normalized = BridgeConfig::from_toml_str(&mixed_case).expect("mixed-case root_domains");
    assert_eq!(normalized.root_domains, vec![".roguefairy.net"]);

    let mut direct_mixed = cfg.clone();
    direct_mixed.root_domains = vec![".RogueFairy.NET".to_owned()];
    assert!(
        direct_mixed.validate().is_ok(),
        "validate() must match root_domains case-insensitively even on programmatic BridgeConfig"
    );

    let empty_explicit = format!("{MINIMAL_VALID_TOML}\nroot_domains = []\n");
    assert!(matches!(
        BridgeConfig::from_toml_str(&empty_explicit),
        Err(ConfigError::EmptyField {
            field: "root_domains"
        })
    ));

    let missing_issuer =
        format!("{MINIMAL_VALID_TOML}\nroot_domains = [\"lore.roguefairy.net\"]\n");
    assert!(matches!(
        BridgeConfig::from_toml_str(&missing_issuer),
        Err(ConfigError::UncoveredRootDomain {
            field: "issuer",
            ..
        })
    ));

    let missing_audience =
        format!("{MINIMAL_VALID_TOML}\nroot_domains = [\"lore-auth.roguefairy.net\"]\n");
    assert!(matches!(
        BridgeConfig::from_toml_str(&missing_audience),
        Err(ConfigError::UncoveredRootDomain {
            field: "audience",
            ..
        })
    ));

    let suffix_collision = format!("{MINIMAL_VALID_TOML}\nroot_domains = [\"adroguefairy.net\"]\n");
    assert!(matches!(
        BridgeConfig::from_toml_str(&suffix_collision),
        Err(ConfigError::UncoveredRootDomain { .. })
    ));
}

#[test]
fn policy_validation_rejects_overlapping_groups_blank_project_groups_and_clears_empty_env_groups() {
    let emp_partner_overlap = format!(
        "{MINIMAL_VALID_TOML}\n[policy]\nemployee_group = \"Shared\"\npartner_group = \"Shared\"\n"
    );
    assert!(matches!(
        BridgeConfig::from_toml_str(&emp_partner_overlap),
        Err(ConfigError::OverlappingPolicyGroups { .. })
    ));

    let admin_partner_overlap = format!(
        "{MINIMAL_VALID_TOML}\n[policy]\nadmin_groups = [\"Shared\"]\npartner_group = \"Shared\"\n"
    );
    assert!(matches!(
        BridgeConfig::from_toml_str(&admin_partner_overlap),
        Err(ConfigError::OverlappingPolicyGroups { .. })
    ));

    for key in [
        "sub",
        "root_domains",
        "resources",
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
        "https://lore.org/claims/root_domains",
    ] {
        let reserved_claims_key =
            format!("{MINIMAL_VALID_TOML}\n[policy]\nclaims_key = \"{key}\"\n");
        assert!(
            matches!(
                BridgeConfig::from_toml_str(&reserved_claims_key),
                Err(ConfigError::ReservedClaimsKey { .. })
            ),
            "reserved JWT claim '{key}' must be rejected as policy.claims_key"
        );
    }

    let blank_lead_group = format!(
        "{MINIMAL_VALID_TOML}\n[projects.ghostlore]\nvisibility = \"internal\"\nlead_groups = [\"  \"]\n"
    );
    assert!(matches!(
        BridgeConfig::from_toml_str(&blank_lead_group),
        Err(ConfigError::EmptyField {
            field: "projects.lead_groups"
        })
    ));

    let file = TempFile::with_contents("bridge-cfg-clear-policy-", MINIMAL_VALID_TOML.as_bytes());
    let mut env = HashMap::new();
    env.insert("RFS_LORE_POLICY_ADMIN_GROUPS".to_owned(), String::new());
    env.insert("RFS_LORE_POLICY_EMPLOYEE_GROUP".to_owned(), String::new());
    env.insert("RFS_LORE_POLICY_PARTNER_GROUP".to_owned(), String::new());
    let cleared = BridgeConfig::load(Some(file.path()), |k| env.get(k).cloned())
        .expect("empty policy group env vars must clear defaults");
    assert!(cleared.policy.admin_groups.is_empty());
    assert!(cleared.policy.employee_group.is_empty());
    assert!(cleared.policy.partner_group.is_empty());
}

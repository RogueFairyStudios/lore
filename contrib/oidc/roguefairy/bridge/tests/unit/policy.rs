// SPDX-FileCopyrightText: 2026 Rogue Fairy Studios
// SPDX-License-Identifier: MIT

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::str::FromStr;

use lore_base::types::Context;
use lore_base::types::RepositoryId;
use rfs_lore_bridge::config::StaticProjectConfig;
use rfs_lore_bridge::config::UserIdField;
use rfs_lore_bridge::error::PolicyError;
use rfs_lore_bridge::policy::ActionSet;
use rfs_lore_bridge::policy::CallerClaims;
use rfs_lore_bridge::policy::GROUP_C_LEVEL;
use rfs_lore_bridge::policy::GROUP_EMPLOYEES;
use rfs_lore_bridge::policy::GROUP_PARTNERS;
use rfs_lore_bridge::policy::LoreAction;
use rfs_lore_bridge::policy::PresentStringClaim;
use rfs_lore_bridge::policy::ProjectVisibility;
use rfs_lore_bridge::policy::RawLoginClaims;
use rfs_lore_bridge::policy::RawRfsLoreClaim;
use rfs_lore_bridge::policy::RawRfsProjectClaim;
use rfs_lore_bridge::policy::VerifiedCaller;
use rfs_lore_bridge::policy::VerifiedExchangedCaller;
use rfs_lore_bridge::policy::granted_action_set_on_project;
use rfs_lore_bridge::policy::may_access_partition;
use rfs_lore_bridge::policy::may_create_repository;
use rfs_lore_bridge::policy::may_unregister_repository;
use rfs_lore_bridge::policy::parse_project_repository_name;
use rfs_lore_bridge::store::RepositoryRecord;

fn granted_actions_on_project(
    caller: &CallerClaims,
    project: &str,
    visibility: ProjectVisibility,
) -> BTreeSet<LoreAction> {
    granted_action_set_on_project(caller, project, visibility)
        .iter()
        .collect()
}

fn base_login_claims(username: &str) -> RawLoginClaims {
    RawLoginClaims {
        sub: format!("sub-{username}"),
        exp: 4_102_444_800,
        nbf: None,
        iat: Some(1_700_000_000),
        identity: Some(PresentStringClaim::Valid(username.to_owned())),
        identity_namespaced: None,
        preferred_username: Some(username.to_owned()),
        name: Some(format!("Display {username}")),
        is_service_account: Some(false),
        groups: None,
        rfs_lore: None,
    }
}

#[test]
fn project_repository_name_validation_covers_boundaries() {
    let parsed = parse_project_repository_name("ghostlore/game").expect("valid project/repo");
    assert_eq!(parsed.project, "ghostlore");
    assert_eq!(parsed.full_name, "ghostlore/game");

    let nested = parse_project_repository_name("animafaber/tools/core-sdk")
        .expect("multi-segment repo under project is valid");
    assert_eq!(nested.project, "animafaber");
    assert_eq!(nested.full_name, "animafaber/tools/core-sdk");

    assert_eq!(
        parse_project_repository_name("standalone"),
        Err(PolicyError::MissingProjectNamespace)
    );
    assert_eq!(
        parse_project_repository_name("ghostlore/"),
        Err(PolicyError::MissingProjectNamespace)
    );
    assert!(matches!(
        parse_project_repository_name("GhostLore/game"),
        Err(PolicyError::InvalidProjectSlug { .. })
    ));
    assert!(matches!(
        parse_project_repository_name("-bad/game"),
        Err(PolicyError::InvalidProjectSlug { .. })
    ));
    assert!(matches!(
        parse_project_repository_name("ghostlore/.hidden"),
        Err(PolicyError::InvalidRepositorySegment { .. })
    ));
    assert!(matches!(
        parse_project_repository_name("ghostlore/a//b"),
        Err(PolicyError::InvalidRepositorySegment { .. })
    ));

    let too_long = format!("ghostlore/{}", "a".repeat(1000));
    assert_eq!(
        parse_project_repository_name(&too_long),
        Err(PolicyError::InvalidRepositoryNameLength)
    );
}

#[test]
fn c_level_holds_all_actions_and_global_create() {
    let mut raw = base_login_claims("alice");
    raw.groups = Some(vec![GROUP_C_LEVEL.to_owned()]);
    let caller = CallerClaims::from_login_claims(raw, &BTreeMap::new(), UserIdField::Username)
        .expect("caller");

    assert!(may_create_repository(&caller, "ghostlore"));
    assert!(may_create_repository(&caller, "brand-new-project"));

    let internal = granted_actions_on_project(&caller, "ghostlore", ProjectVisibility::Internal);
    let restricted =
        granted_actions_on_project(&caller, "secretproto", ProjectVisibility::Restricted);
    assert_eq!(internal.len(), LoreAction::ALL.len());
    assert_eq!(restricted.len(), LoreAction::ALL.len());
}

#[test]
fn employee_accesses_internal_projects_only_and_cannot_create_without_lead_grant() {
    let mut raw = base_login_claims("bruno");
    raw.rfs_lore = Some(RawRfsLoreClaim {
        is_employee: true,
        ..RawRfsLoreClaim::default()
    });
    let bruno = CallerClaims::from_login_claims(raw, &BTreeMap::new(), UserIdField::Username)
        .expect("bruno");

    assert!(!may_create_repository(&bruno, "ghostlore"));
    assert_eq!(
        granted_actions_on_project(&bruno, "ghostlore", ProjectVisibility::Internal),
        BTreeSet::from([LoreAction::Read, LoreAction::Write])
    );
    assert!(
        granted_actions_on_project(&bruno, "secretproto", ProjectVisibility::Restricted).is_empty()
    );
}

#[test]
fn partner_has_zero_global_access_and_strictly_scoped_project_access() {
    let mut raw_unassigned = base_login_claims("eva");
    raw_unassigned.rfs_lore = Some(RawRfsLoreClaim {
        is_partner: true,
        ..RawRfsLoreClaim::default()
    });
    let eva =
        CallerClaims::from_login_claims(raw_unassigned, &BTreeMap::new(), UserIdField::Username)
            .expect("eva");
    assert!(granted_actions_on_project(&eva, "ghostlore", ProjectVisibility::Internal).is_empty());

    let mut projects = BTreeMap::new();
    projects.insert(
        "ghostlore".to_owned(),
        RawRfsProjectClaim {
            actions: ActionSet::from_slice(&[LoreAction::Read]),
            can_create_repo: false,
            visibility: ProjectVisibility::Internal,
        },
    );
    let mut raw_diego = base_login_claims("diego");
    raw_diego.rfs_lore = Some(RawRfsLoreClaim {
        is_partner: true,
        projects,
        ..RawRfsLoreClaim::default()
    });
    let diego = CallerClaims::from_login_claims(raw_diego, &BTreeMap::new(), UserIdField::Username)
        .expect("diego");

    assert_eq!(
        granted_actions_on_project(&diego, "ghostlore", ProjectVisibility::Internal),
        BTreeSet::from([LoreAction::Read])
    );
    assert!(
        granted_actions_on_project(&diego, "animafaber", ProjectVisibility::Internal).is_empty()
    );
    assert!(!may_create_repository(&diego, "ghostlore"));
}

#[test]
fn dual_employee_and_partner_membership_fails_closed_without_c_level() {
    let mut raw = base_login_claims("misconfigured");
    raw.groups = Some(vec![GROUP_EMPLOYEES.to_owned(), GROUP_PARTNERS.to_owned()]);
    let caller = CallerClaims::from_login_claims(raw, &BTreeMap::new(), UserIdField::Username)
        .expect("caller");

    assert!(
        granted_actions_on_project(&caller, "ghostlore", ProjectVisibility::Internal).is_empty()
    );
}

#[test]
fn static_project_group_mappings_augment_plain_oidc_groups() {
    let mut static_projects = BTreeMap::new();
    static_projects.insert(
        "geppetto".to_owned(),
        StaticProjectConfig {
            visibility: ProjectVisibility::Internal,
            read_groups: Vec::new(),
            write_groups: Vec::new(),
            lead_groups: vec!["Rogue Fairy Studios - Geppetto Leads".to_owned()],
        },
    );

    let mut raw = base_login_claims("lead");
    raw.groups = Some(vec!["Rogue Fairy Studios - Geppetto Leads".to_owned()]);
    let caller = CallerClaims::from_login_claims(raw, &static_projects, UserIdField::Username)
        .expect("caller");

    assert!(may_create_repository(&caller, "geppetto"));
    let actions = granted_actions_on_project(&caller, "geppetto", ProjectVisibility::Internal);
    assert!(actions.contains(&LoreAction::Admin));
    assert!(actions.contains(&LoreAction::Write));
}

#[test]
fn unregister_honors_both_login_and_exchanged_tokens() {
    let repo_id =
        RepositoryId::from(Context::from_str("11111111111111111111111111111111").expect("id"));
    let repo = RepositoryRecord {
        id: repo_id,
        name: "ghostlore/game".to_owned(),
        project: "ghostlore".to_owned(),
        visibility: ProjectVisibility::Internal,
        creator: "carla".to_owned(),
        created_at: 100,
    };

    let bruno_exchanged = VerifiedCaller::Exchanged(VerifiedExchangedCaller {
        identity: "bruno".to_owned(),
        repository_id: repo_id,
        actions: ActionSet::from_slice(&[LoreAction::Read, LoreAction::Write]),
    });
    assert!(!may_unregister_repository(
        &bruno_exchanged,
        &repo,
        ProjectVisibility::Internal,
        UserIdField::Username,
    ));

    let creator_exchanged = VerifiedCaller::Exchanged(VerifiedExchangedCaller {
        identity: "carla".to_owned(),
        repository_id: repo_id,
        actions: ActionSet::from_slice(&[LoreAction::Read, LoreAction::Write]),
    });
    assert!(may_unregister_repository(
        &creator_exchanged,
        &repo,
        ProjectVisibility::Internal,
        UserIdField::Username,
    ));

    let empty_perm_exchanged = VerifiedCaller::Exchanged(VerifiedExchangedCaller {
        identity: "diego".to_owned(),
        repository_id: repo_id,
        actions: ActionSet::EMPTY,
    });
    assert!(!may_access_partition(
        &empty_perm_exchanged,
        &repo,
        ProjectVisibility::Internal
    ));
}

#[test]
fn empty_sub_in_login_claims_is_rejected_even_with_explicit_identity() {
    let mut raw = base_login_claims("alice");
    raw.sub.clear();
    assert!(
        CallerClaims::from_login_claims(raw, &BTreeMap::new(), UserIdField::Username).is_none()
    );
}

#[test]
fn unregister_requires_admin_owner_or_creator_write_not_create_flag() {
    let repo_id =
        RepositoryId::from(Context::from_str("44444444444444444444444444444444").expect("id"));
    let restricted_repo = RepositoryRecord {
        id: repo_id,
        name: "secretproto/engine".to_owned(),
        project: "secretproto".to_owned(),
        visibility: ProjectVisibility::Restricted,
        creator: "carla".to_owned(),
        created_at: 100,
    };

    let mut raw_any_creator = base_login_claims("helper");
    raw_any_creator.rfs_lore = Some(RawRfsLoreClaim {
        can_create_any: true,
        ..RawRfsLoreClaim::default()
    });
    let any_creator = VerifiedCaller::Login(Box::new(
        CallerClaims::from_login_claims(raw_any_creator, &BTreeMap::new(), UserIdField::Username)
            .expect("caller"),
    ));
    assert!(
        !may_unregister_repository(
            &any_creator,
            &restricted_repo,
            ProjectVisibility::Restricted,
            UserIdField::Username,
        ),
        "can_create_any without Owner/Admin/creator+Write must not unregister restricted repos"
    );

    let mut projects = BTreeMap::new();
    projects.insert(
        "ghostlore".to_owned(),
        RawRfsProjectClaim {
            actions: ActionSet::from_slice(&[LoreAction::Read, LoreAction::Write]),
            can_create_repo: true,
            visibility: ProjectVisibility::Internal,
        },
    );
    let mut raw_peer = base_login_claims("peer_creator");
    raw_peer.rfs_lore = Some(RawRfsLoreClaim {
        is_employee: true,
        projects,
        ..RawRfsLoreClaim::default()
    });
    let peer = VerifiedCaller::Login(Box::new(
        CallerClaims::from_login_claims(raw_peer, &BTreeMap::new(), UserIdField::Username)
            .expect("peer"),
    ));
    let coworker_repo = RepositoryRecord {
        id: repo_id,
        name: "ghostlore/game".to_owned(),
        project: "ghostlore".to_owned(),
        visibility: ProjectVisibility::Internal,
        creator: "carla".to_owned(),
        created_at: 100,
    };
    assert!(
        !may_unregister_repository(
            &peer,
            &coworker_repo,
            ProjectVisibility::Internal,
            UserIdField::Username,
        ),
        "can_create_repo without Owner/Admin must not delete a teammate's repository"
    );
}

#[test]
fn misspelled_visibility_in_login_claims_fails_closed_to_restricted() {
    let raw: RawLoginClaims = serde_json::from_value(serde_json::json!({
        "iss": "https://auth.telluriancorp.info/application/o/rfs-lore-cli/",
        "sub": "sub-carla",
        "aud": ["https://lore.roguefairy.net"],
        "exp": 4_102_444_800_u64,
        "identity": "carla",
        "preferred_username": "carla",
        "name": "Display carla",
        "is_service_account": false,
        "rfs_lore": {
            "is_employee": true,
            "projects": {
                "secretproto": {
                    "actions": ["read", "write", "admin"],
                    "can_create_repo": true,
                    "visibility": "restrcited"
                }
            }
        }
    }))
    .expect("deserialize RawLoginClaims");
    let caller = CallerClaims::from_login_claims(raw, &BTreeMap::new(), UserIdField::Username)
        .expect("caller");
    assert_eq!(
        caller.projects["secretproto"].visibility,
        ProjectVisibility::Restricted,
        "unrecognized lore_visibility values must fail closed to Restricted"
    );
}

#[test]
fn exchanged_token_with_write_without_explicit_read_permits_partition_access() {
    let repo_id =
        RepositoryId::from(Context::from_str("77777777777777777777777777777777").expect("id"));
    let repo = RepositoryRecord {
        id: repo_id,
        name: "ghostlore/game".to_owned(),
        project: "ghostlore".to_owned(),
        visibility: ProjectVisibility::Internal,
        creator: "carla".to_owned(),
        created_at: 100,
    };
    let write_only_exchanged = VerifiedCaller::Exchanged(VerifiedExchangedCaller {
        identity: "bruno".to_owned(),
        repository_id: repo_id,
        actions: ActionSet::from_slice(&[LoreAction::Write]),
    });
    assert!(
        may_access_partition(&write_only_exchanged, &repo, ProjectVisibility::Internal),
        "any valid Lore action on an exchanged at+jwt must permit partition directory queries"
    );
}

#[test]
fn login_claim_project_visibility_constrains_employee_actions_and_unregister() {
    let repo_id =
        RepositoryId::from(Context::from_str("dededededededededededededededede").expect("hex"));
    let repo = RepositoryRecord {
        id: repo_id,
        name: "ghostlore/client".to_owned(),
        project: "ghostlore".to_owned(),
        visibility: ProjectVisibility::Internal,
        creator: "bruno".to_owned(),
        created_at: 1,
    };

    let mut read_only_restricted = base_login_claims("bruno");
    let mut projects = BTreeMap::new();
    projects.insert(
        "ghostlore".to_owned(),
        RawRfsProjectClaim {
            actions: ActionSet::from_slice(&[LoreAction::Read]),
            can_create_repo: false,
            visibility: ProjectVisibility::Restricted,
        },
    );
    read_only_restricted.rfs_lore = Some(RawRfsLoreClaim {
        is_c_level: false,
        is_employee: true,
        is_partner: false,
        can_create_any: false,
        global_actions: ActionSet::EMPTY,
        projects,
    });
    let caller = CallerClaims::from_login_claims(
        read_only_restricted,
        &BTreeMap::new(),
        UserIdField::Username,
    )
    .expect("caller claims");
    assert_eq!(
        granted_actions_on_project(&caller, "ghostlore", ProjectVisibility::Internal),
        BTreeSet::from([LoreAction::Read]),
        "restricted project visibility in token claim must prevent baseline employee write expansion"
    );
    assert!(
        !may_unregister_repository(
            &VerifiedCaller::Login(Box::new(caller)),
            &repo,
            ProjectVisibility::Internal,
            UserIdField::Username,
        ),
        "creator without admin/owner on a claim-restricted project must not unregister"
    );

    let mut zero_grant_restricted = base_login_claims("bruno");
    let mut empty_projects = BTreeMap::new();
    empty_projects.insert(
        "ghostlore".to_owned(),
        RawRfsProjectClaim {
            actions: ActionSet::EMPTY,
            can_create_repo: false,
            visibility: ProjectVisibility::Restricted,
        },
    );
    zero_grant_restricted.rfs_lore = Some(RawRfsLoreClaim {
        is_c_level: false,
        is_employee: true,
        is_partner: false,
        can_create_any: false,
        global_actions: ActionSet::EMPTY,
        projects: empty_projects,
    });
    let zero_caller = CallerClaims::from_login_claims(
        zero_grant_restricted,
        &BTreeMap::new(),
        UserIdField::Username,
    )
    .expect("zero-grant caller claims");
    assert!(
        granted_actions_on_project(&zero_caller, "ghostlore", ProjectVisibility::Internal)
            .is_empty(),
        "empty grant carrying visibility=restricted must still latch restricted visibility"
    );
    assert!(
        !may_access_partition(
            &VerifiedCaller::Login(Box::new(zero_caller)),
            &repo,
            ProjectVisibility::Internal
        ),
        "partition access must fail closed when token marks project restricted with empty actions"
    );
}

#[test]
fn overlapping_policy_groups_in_direct_struct_set_both_flags_and_fail_closed() {
    let policy = rfs_lore_bridge::config::PolicyConfig {
        admin_groups: vec![GROUP_C_LEVEL.to_owned()],
        employee_group: "Shared Group".to_owned(),
        partner_group: "Shared Group".to_owned(),
        claims_key: "rfs_lore".to_owned(),
    };
    let mut raw = base_login_claims("overlap_user");
    raw.groups = Some(vec!["Shared Group".to_owned()]);

    let caller = CallerClaims::from_login_claims_with_policy(
        raw,
        &BTreeMap::new(),
        UserIdField::Username,
        &policy,
    )
    .expect("caller claims");
    assert!(caller.is_employee);
    assert!(caller.is_partner);
    assert!(
        granted_actions_on_project(&caller, "ghostlore", ProjectVisibility::Internal).is_empty(),
        "partner fail-closed invariant must suppress employee baseline grants when groups overlap"
    );
}

#[test]
fn login_claims_reject_invalid_identity_sanitize_user_fields_and_merge_static_visibility() {
    let mut ctrl_id = base_login_claims("alice");
    ctrl_id.identity = Some(PresentStringClaim::Valid("bad\nuser".to_owned()));
    assert!(
        CallerClaims::from_login_claims(ctrl_id, &BTreeMap::new(), UserIdField::Username).is_none(),
        "control characters in login identity must be rejected"
    );

    let mut oversized_id = base_login_claims("alice");
    oversized_id.identity = Some(PresentStringClaim::Valid("a".repeat(257)));
    assert!(
        CallerClaims::from_login_claims(oversized_id, &BTreeMap::new(), UserIdField::Username)
            .is_none(),
        "login identity exceeding MAX_USER_ID_BYTES must be rejected"
    );

    let nested_non_string: RawLoginClaims = serde_json::from_value(serde_json::json!({
        "sub": "sub-alice",
        "exp": 4_102_444_800_u64,
        "identity": [{"nested": [1, 2, {"deep": true}]}]
    }))
    .expect("PresentStringClaim must skip nested JSON without failing deserialization");
    assert_eq!(
        nested_non_string.identity,
        Some(PresentStringClaim::Invalid)
    );
    assert!(
        CallerClaims::from_login_claims(nested_non_string, &BTreeMap::new(), UserIdField::Username)
            .is_none(),
        "non-string present identity claim must fail closed"
    );

    let mut dirty_profile = base_login_claims("carla");
    dirty_profile.preferred_username = Some("bad\x07username".to_owned());
    dirty_profile.name = Some("x".repeat(600));
    let sanitized =
        CallerClaims::from_login_claims(dirty_profile, &BTreeMap::new(), UserIdField::Username)
            .expect("valid identity with dirty profile fields must sanitize rather than panic");
    assert_eq!(sanitized.username, "carla");
    assert_eq!(sanitized.display_name, "carla");

    let mut static_projects = BTreeMap::new();
    static_projects.insert(
        "secretproto".to_owned(),
        StaticProjectConfig {
            visibility: ProjectVisibility::Restricted,
            read_groups: Vec::new(),
            write_groups: Vec::new(),
            lead_groups: Vec::new(),
        },
    );
    let raw_from_json: RawLoginClaims = serde_json::from_value(serde_json::json!({
        "iss": "https://auth.telluriancorp.info/application/o/rfs-lore-cli/",
        "sub": "sub-carla",
        "aud": "https://lore.roguefairy.net",
        "exp": 4_102_444_800_u64,
        "identity": "carla",
        "rfs_lore": {
            "is_employee": true,
            "projects": {
                "secretproto": {
                    "actions": ["read", "write"],
                    "can_create_repo": false
                },
                "typoproj": {
                    "actions": ["read"],
                    "can_create_repo": false,
                    "visibility": "restrcited"
                }
            }
        }
    }))
    .expect("deserialize RawLoginClaims JSON");
    let merged =
        CallerClaims::from_login_claims(raw_from_json, &static_projects, UserIdField::Username)
            .expect("caller claims");
    assert_eq!(
        merged.projects["secretproto"].visibility,
        ProjectVisibility::Restricted,
        "static [projects.<slug>] visibility must merge into rfs_lore project grants even without OIDC groups"
    );
    assert_eq!(
        merged.projects["typoproj"].visibility,
        ProjectVisibility::Restricted,
        "misspelled visibility in JSON must deserialize fail-closed as Restricted"
    );

    let mut squatter = base_login_claims("bob");
    squatter.preferred_username = Some("carla".to_owned());
    let bob = CallerClaims::from_login_claims(squatter, &BTreeMap::new(), UserIdField::Username)
        .expect("bob claims");
    assert_eq!(
        bob.username, "bob",
        "Username mode must bind username to canonical identity to prevent preferred_username squatting"
    );
}

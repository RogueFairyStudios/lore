// SPDX-FileCopyrightText: 2026 Rogue Fairy Studios
// SPDX-License-Identifier: MIT

use std::str::FromStr;

use lore_base::test_util::TempDir;
use lore_base::types::Context;
use lore_base::types::RepositoryId;
use rfs_lore_bridge::config::UserIdField;
use rfs_lore_bridge::error::StoreError;
use rfs_lore_bridge::policy::ProjectVisibility;
use rfs_lore_bridge::store::BridgeStore;
use rfs_lore_bridge::store::RepositoryRecord;
use rfs_lore_bridge::store::UserRecord;

fn id(hex_str: &str) -> RepositoryId {
    RepositoryId::from(Context::from_str(hex_str).expect("valid 32-hex id"))
}

#[tokio::test]
async fn store_persists_across_reopen_and_enforces_uniqueness() {
    let dir = TempDir::new("rfs-bridge-store-");
    let state_path = dir.child("state.json");

    let id_one = id("11111111111111111111111111111111");
    let id_two = id("22222222222222222222222222222222");

    {
        let store = BridgeStore::open(Some(state_path.clone())).expect("open store");
        let rec = RepositoryRecord {
            id: id_one,
            name: "ghostlore/game".to_owned(),
            project: "ghostlore".to_owned(),
            visibility: ProjectVisibility::Internal,
            creator: "carla".to_owned(),
            created_at: 1_700_000_000,
        };
        store
            .register_repository(rec.clone())
            .await
            .expect("register");
        store
            .register_repository(rec)
            .await
            .expect("idempotent retry under same id and name succeeds");

        let wrong_name = RepositoryRecord {
            id: id_one,
            name: "ghostlore/other".to_owned(),
            project: "ghostlore".to_owned(),
            visibility: ProjectVisibility::Internal,
            creator: "carla".to_owned(),
            created_at: 1_700_000_001,
        };
        assert!(matches!(
            store.register_repository(wrong_name).await,
            Err(StoreError::RepositoryIdConflict { .. })
        ));

        let wrong_id = RepositoryRecord {
            id: id_two,
            name: "ghostlore/game".to_owned(),
            project: "ghostlore".to_owned(),
            visibility: ProjectVisibility::Internal,
            creator: "carla".to_owned(),
            created_at: 1_700_000_001,
        };
        assert!(matches!(
            store.register_repository(wrong_id).await,
            Err(StoreError::RepositoryNameConflict { .. })
        ));

        store
            .upsert_user(UserRecord {
                id: "carla".to_owned(),
                username: "carla".to_owned(),
                display_name: "Carla Lead".to_owned(),
            })
            .await
            .expect("upsert user");
    }

    let reopened = BridgeStore::open(Some(state_path)).expect("reopen store");
    let loaded = reopened
        .get_repository(id_one)
        .expect("repository survives reopen");
    assert_eq!(loaded.name, "ghostlore/game");
    assert_eq!(reopened.find_by_username("carla").len(), 1);
}

#[tokio::test]
async fn restricted_visibility_promotes_monotonically_and_capacity_bounds_hold() {
    let store = BridgeStore::open_with_limits(None, 2, 1).expect("in-memory bounded store");
    let id_a = id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let id_b = id("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    let id_c = id("cccccccccccccccccccccccccccccccc");

    store
        .register_repository(RepositoryRecord {
            id: id_a,
            name: "secretproto/alpha".to_owned(),
            project: "secretproto".to_owned(),
            visibility: ProjectVisibility::Internal,
            creator: "alice".to_owned(),
            created_at: 1,
        })
        .await
        .expect("register alpha");

    store
        .register_repository(RepositoryRecord {
            id: id_b,
            name: "secretproto/beta".to_owned(),
            project: "secretproto".to_owned(),
            visibility: ProjectVisibility::Restricted,
            creator: "carla".to_owned(),
            created_at: 2,
        })
        .await
        .expect("register beta as restricted");

    assert_eq!(
        store.get_repository(id_a).expect("alpha").visibility,
        ProjectVisibility::Restricted
    );

    let past_limit = store
        .register_repository(RepositoryRecord {
            id: id_c,
            name: "ghostlore/gamma".to_owned(),
            project: "ghostlore".to_owned(),
            visibility: ProjectVisibility::Internal,
            creator: "alice".to_owned(),
            created_at: 3,
        })
        .await;
    assert!(matches!(
        past_limit,
        Err(StoreError::CapacityExceeded { limit: 2 })
    ));

    store
        .upsert_user(UserRecord {
            id: "u1".to_owned(),
            username: "u1".to_owned(),
            display_name: "User 1".to_owned(),
        })
        .await
        .expect("first user fits");
    let second_user = store
        .upsert_user(UserRecord {
            id: "u2".to_owned(),
            username: "u2".to_owned(),
            display_name: "User 2".to_owned(),
        })
        .await;
    assert!(matches!(
        second_user,
        Err(StoreError::CapacityExceeded { limit: 1 })
    ));
}

#[test]
fn reopen_enforces_capacity_and_name_invariants_on_persisted_state() {
    let dir = TempDir::new("rfs-bridge-store-bounds-");
    let over_cap_path = dir.child("over_cap.json");
    std::fs::write(
        &over_cap_path,
        r#"{
  "version": 1,
  "repositories": [
    {
      "id": "11111111111111111111111111111111",
      "name": "ghostlore/one",
      "project": "ghostlore",
      "visibility": "internal",
      "creator": "carla",
      "created_at": 1
    },
    {
      "id": "22222222222222222222222222222222",
      "name": "ghostlore/two",
      "project": "ghostlore",
      "visibility": "internal",
      "creator": "carla",
      "created_at": 2
    }
  ],
  "project_visibilities": {},
  "users": []
}"#,
    )
    .expect("write over_cap.json");
    assert!(matches!(
        BridgeStore::open_with_limits(Some(over_cap_path), 1, 10),
        Err(StoreError::CapacityExceeded { limit: 1 })
    ));

    let bad_name_path = dir.child("bad_name.json");
    std::fs::write(
        &bad_name_path,
        r#"{
  "version": 1,
  "repositories": [
    {
      "id": "11111111111111111111111111111111",
      "name": "standalone-without-project",
      "project": "ghostlore",
      "visibility": "internal",
      "creator": "carla",
      "created_at": 1
    }
  ],
  "project_visibilities": {},
  "users": []
}"#,
    )
    .expect("write bad_name.json");
    assert!(
        matches!(
            BridgeStore::open_with_limits(Some(bad_name_path), 10, 10),
            Err(StoreError::InvalidPersistedRepository { .. })
        ),
        "persisted repository missing <project>/<repo> namespace must fail with InvalidPersistedRepository"
    );
}

#[tokio::test]
async fn cancelled_persistence_keeps_disk_and_memory_consistent() {
    use std::sync::Arc;

    use lore_base::lore_spawn;
    use rfs_lore_bridge::store::test_util::PersistPark;

    let dir = TempDir::new("rfs-bridge-store-cancel-");
    let state_path = dir.child("state.json");
    let store = Arc::new(BridgeStore::open(Some(state_path.clone())).expect("open store"));
    let repo_a = id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let mut park = PersistPark::arm(&state_path);
    let store_for_a = store.clone();
    let handle_a = lore_spawn!(async move {
        store_for_a
            .register_repository(RepositoryRecord {
                id: repo_a,
                name: "ghostlore/cancelled-rpc".to_owned(),
                project: "ghostlore".to_owned(),
                visibility: ProjectVisibility::Internal,
                creator: "carla".to_owned(),
                created_at: 100,
            })
            .await
    });

    park.entered().await;
    handle_a.abort();
    let _ = handle_a.await;

    let store_for_b = store.clone();
    let handle_b = lore_spawn!(async move {
        store_for_b
            .upsert_user(UserRecord {
                id: "bruno".to_owned(),
                username: "bruno".to_owned(),
                display_name: "Bruno Dev".to_owned(),
            })
            .await
    });

    park.release();
    handle_b
        .await
        .expect("join write b")
        .expect("write b must succeed");

    let reopened = BridgeStore::open(Some(state_path)).expect("reopen after cancelled write");
    assert!(
        store.get_repository(repo_a).is_some(),
        "in-flight write already committed on blocking thread must update in-memory store"
    );
    assert_eq!(
        reopened.get_repository(repo_a),
        store.get_repository(repo_a),
        "disk state and in-memory store must never diverge after future cancellation"
    );
    assert_eq!(reopened.find_by_username("bruno").len(), 1);
}

#[tokio::test]
async fn username_reassignment_keeps_single_owner_and_unregister_prunes_internal_project() {
    let dir = TempDir::new("rfs-bridge-store-username-");
    let state_path = dir.child("state.json");
    let repo_one = id("33333333333333333333333333333333");

    let uuid_old = "00000000-0000-4000-8000-000000000001";
    let uuid_new = "00000000-0000-4000-8000-000000000002";

    {
        let store =
            BridgeStore::open_with_user_id_field(Some(state_path.clone()), UserIdField::Uuid)
                .expect("open store");
        store
            .upsert_user(UserRecord {
                id: uuid_old.to_owned(),
                username: "carla".to_owned(),
                display_name: "Carla Old".to_owned(),
            })
            .await
            .expect("upsert old owner");
        store
            .upsert_user(UserRecord {
                id: uuid_new.to_owned(),
                username: "carla".to_owned(),
                display_name: "Carla New".to_owned(),
            })
            .await
            .expect("upsert new owner");

        let by_username = store.find_by_username("carla");
        assert_eq!(by_username.len(), 1);
        assert_eq!(by_username[0].id, uuid_new);

        store
            .register_repository(RepositoryRecord {
                id: repo_one,
                name: "ephemeralproj/game".to_owned(),
                project: "ephemeralproj".to_owned(),
                visibility: ProjectVisibility::Internal,
                creator: uuid_new.to_owned(),
                created_at: 10,
            })
            .await
            .expect("register ephemeralproj/game");
        assert_eq!(
            store.project_visibility("ephemeralproj"),
            Some(ProjectVisibility::Internal)
        );

        assert!(
            store
                .unregister_repository(repo_one)
                .await
                .expect("unregister")
        );
        assert_eq!(store.project_visibility("ephemeralproj"), None);
    }

    let reopened =
        BridgeStore::open_with_user_id_field(Some(state_path), UserIdField::Uuid).expect("reopen");
    let by_username = reopened.find_by_username("carla");
    assert_eq!(by_username.len(), 1);
    assert_eq!(by_username[0].id, uuid_new);
}

#[tokio::test]
async fn restricted_project_tombstones_do_not_exhaust_active_repository_capacity() {
    let store = BridgeStore::open_with_limits(None, 2, 10).expect("open bounded store");

    for idx in 0..2_u8 {
        let repo = id(&format!("{:032x}", u128::from(idx) + 1));
        let project = format!("restricted-{idx}");
        store
            .register_repository(RepositoryRecord {
                id: repo,
                name: format!("{project}/main"),
                project: project.clone(),
                visibility: ProjectVisibility::Restricted,
                creator: "carla".to_owned(),
                created_at: u64::from(idx) + 1,
            })
            .await
            .expect("register restricted repo");
        assert!(
            store
                .unregister_repository(repo)
                .await
                .expect("unregister restricted repo")
        );
        assert_eq!(
            store.project_visibility(&project),
            Some(ProjectVisibility::Restricted),
            "restricted visibility tombstone must stay latched after unregister"
        );
    }

    let fresh_repo = id("00000000000000000000000000000099");
    store
        .register_repository(RepositoryRecord {
            id: fresh_repo,
            name: "ghostlore/fresh".to_owned(),
            project: "ghostlore".to_owned(),
            visibility: ProjectVisibility::Internal,
            creator: "carla".to_owned(),
            created_at: 99,
        })
        .await
        .expect("retained restricted tombstones must not block active repository capacity");
    store
        .unregister_repository(fresh_repo)
        .await
        .expect("unregister fresh_repo");

    for idx in 2..8_u8 {
        let repo = id(&format!("{:032x}", u128::from(idx) + 1));
        let project = format!("restricted-{idx}");
        store
            .register_repository(RepositoryRecord {
                id: repo,
                name: format!("{project}/main"),
                project,
                visibility: ProjectVisibility::Restricted,
                creator: "carla".to_owned(),
                created_at: u64::from(idx) + 1,
            })
            .await
            .expect("register restricted repo within 4x tombstone bound");
        store
            .unregister_repository(repo)
            .await
            .expect("unregister restricted repo");
    }

    let ninth_project = store
        .register_repository(RepositoryRecord {
            id: id("000000000000000000000000000000aa"),
            name: "ninthproj/main".to_owned(),
            project: "ninthproj".to_owned(),
            visibility: ProjectVisibility::Internal,
            creator: "carla".to_owned(),
            created_at: 200,
        })
        .await;
    assert!(matches!(
        ninth_project,
        Err(StoreError::CapacityExceeded { limit: 8 })
    ));
}

#[tokio::test]
async fn upsert_users_enforces_capacity_without_waiting_on_write_gate_or_partial_mutation() {
    let dir = TempDir::new("rfs-store-user-cap-");
    let state_path = dir.child("registry-state.json");
    let store = std::sync::Arc::new(
        BridgeStore::open_with_limits(Some(state_path.clone()), 10, 2)
            .expect("open user-bounded store"),
    );

    store
        .upsert_users(&[
            UserRecord {
                id: "user1".to_owned(),
                username: "user1".to_owned(),
                display_name: "User One".to_owned(),
            },
            UserRecord {
                id: "user2".to_owned(),
                username: "user2".to_owned(),
                display_name: "User Two".to_owned(),
            },
        ])
        .await
        .expect("populate initial 2 users");

    let mut park = rfs_lore_bridge::store::test_util::PersistPark::arm(&state_path);
    let store_bg = store.clone();
    let bg_register = lore_base::lore_spawn!(async move {
        store_bg
            .register_repository(RepositoryRecord {
                id: id("000000000000000000000000000000bb"),
                name: "ghostlore/parked".to_owned(),
                project: "ghostlore".to_owned(),
                visibility: ProjectVisibility::Internal,
                creator: "user1".to_owned(),
                created_at: 1,
            })
            .await
    });
    park.entered().await;

    // While `write_gate` is held by `bg_register`, a 3rd distinct user must be rejected
    // immediately under the read lock without stalling on `write_gate`.
    let cap_while_parked = tokio::time::timeout(
        std::time::Duration::from_millis(150),
        store.upsert_user(UserRecord {
            id: "user3".to_owned(),
            username: "user3".to_owned(),
            display_name: "User Three".to_owned(),
        }),
    )
    .await
    .expect("capacity rejection must not block on write_gate");
    assert!(matches!(
        cap_while_parked,
        Err(StoreError::CapacityExceeded { limit: 2 })
    ));

    park.release();
    bg_register
        .await
        .expect("join bg_register")
        .expect("register parked repo");

    // Mixed batch updating an existing user + inserting an over-capacity user must fail
    // without partially mutating or persisting the existing user.
    let mixed = store
        .upsert_users(&[
            UserRecord {
                id: "user1".to_owned(),
                username: "user1".to_owned(),
                display_name: "Mutated Before Cap".to_owned(),
            },
            UserRecord {
                id: "user3".to_owned(),
                username: "user3".to_owned(),
                display_name: "User Three".to_owned(),
            },
        ])
        .await;
    assert!(matches!(
        mixed,
        Err(StoreError::CapacityExceeded { limit: 2 })
    ));
    assert_eq!(store.find_by_username("user1")[0].display_name, "User One");
}

#[test]
fn unreadable_or_invalid_state_path_returns_read_error() {
    let dir = TempDir::new("rfs-bridge-store-read-err-");

    let as_dir = dir.child("state-is-a-directory");
    std::fs::create_dir_all(&as_dir).expect("create directory at state_path");
    assert!(
        matches!(
            BridgeStore::open(Some(as_dir)),
            Err(StoreError::ReadState { .. })
        ),
        "directory at state_path must fail with StoreError::ReadState"
    );

    let invalid_nul_path = dir.child("invalid\0state.json");
    assert!(
        matches!(
            BridgeStore::open(Some(invalid_nul_path)),
            Err(StoreError::ReadState { .. })
        ),
        "non-NotFound stat error on state_path must fail with StoreError::ReadState rather than initializing empty state"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let locked_dir = dir.child("locked");
        std::fs::create_dir_all(&locked_dir).expect("create locked dir");
        let state_in_locked = locked_dir.join("registry-state.json");
        std::fs::write(&state_in_locked, br#"{"version":1}"#).expect("seed state");
        std::fs::set_permissions(&locked_dir, std::fs::Permissions::from_mode(0o000))
            .expect("chmod 0000");
        let stat_blocked = std::fs::metadata(&state_in_locked).is_err();
        let res = BridgeStore::open(Some(state_in_locked));
        std::fs::set_permissions(&locked_dir, std::fs::Permissions::from_mode(0o700))
            .expect("restore 0700");
        if stat_blocked {
            assert!(matches!(res, Err(StoreError::ReadState { .. })));
        }
    }
}

#[test]
fn reopen_in_uuid_mode_canonicalizes_persisted_repository_creator() {
    let dir = TempDir::new("rfs-bridge-store-uuid-creator-");
    let state_path = dir.child("registry-state.json");
    let repo = id("61616161616161616161616161616161");
    std::fs::write(
        &state_path,
        r#"{
  "version": 1,
  "repositories": [
    {
      "id": "61616161616161616161616161616161",
      "name": "ghostlore/legacy-compact-creator",
      "project": "ghostlore",
      "visibility": "internal",
      "creator": "9A7B2C1D0000400080000000000000CC",
      "created_at": 42
    }
  ],
  "project_visibilities": {},
  "users": []
}"#,
    )
    .expect("write state_path");

    let store = BridgeStore::open_with_user_id_field(Some(state_path), UserIdField::Uuid)
        .expect("open uuid store");
    let loaded = store.get_repository(repo).expect("loaded repository");
    assert_eq!(loaded.creator, "9a7b2c1d-0000-4000-8000-0000000000cc");
}

async fn register_parked_repository(
    store: std::sync::Arc<BridgeStore>,
    repo: RepositoryId,
) -> Result<std::sync::Arc<RepositoryRecord>, StoreError> {
    store
        .register_repository(RepositoryRecord {
            id: repo,
            name: "ghostlore/split-parked".to_owned(),
            project: "ghostlore".to_owned(),
            visibility: ProjectVisibility::Internal,
            creator: "carla".to_owned(),
            created_at: 100,
        })
        .await
}

#[tokio::test]
async fn split_user_state_path_commits_users_independently_of_repository_write_gate() {
    let dir = TempDir::new("rfs-bridge-store-split-");
    let state_path = dir.child("registry-state.json");
    let user_state_path = dir.child("registry-users.json");
    let repo_id = id("77777777777777777777777777777777");

    let store = std::sync::Arc::new(
        BridgeStore::open_with_paths_and_field(
            Some(state_path.clone()),
            Some(user_state_path.clone()),
            UserIdField::Username,
        )
        .expect("open split store"),
    );

    let mut park = rfs_lore_bridge::store::test_util::PersistPark::arm(&state_path);
    let bg_register = lore_base::lore_spawn!(register_parked_repository(store.clone(), repo_id));
    park.entered().await;

    // While `repo_write_gate` is parked inside `persist_snapshot_blocking(&state_path)`,
    // `upsert_user` writes to `user_state_path` under `user_write_gate` without stalling.
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        store.upsert_user(UserRecord {
            id: "carla".to_owned(),
            username: "carla".to_owned(),
            display_name: "Carla Lead".to_owned(),
        }),
    )
    .await
    .expect("user upsert must not wait on repo_write_gate")
    .expect("persist split user state");

    park.release();
    bg_register
        .await
        .expect("join parked register")
        .expect("commit parked repository");
    drop(store);

    let reopened = BridgeStore::open_with_paths_and_field(
        Some(state_path),
        Some(user_state_path),
        UserIdField::Username,
    )
    .expect("reopen split store");
    assert_eq!(
        reopened
            .get_repository(repo_id)
            .expect("reloaded repo")
            .name,
        "ghostlore/split-parked"
    );
    assert_eq!(reopened.find_by_username("carla").len(), 1);
}

#[tokio::test]
async fn enabling_split_user_state_path_preserves_existing_combined_users_across_repo_write() {
    let dir = TempDir::new("rfs-bridge-store-split-migrate-");
    let state_path = dir.child("registry-state.json");
    let user_state_path = dir.child("users-state.json");
    let existing_repo = id("88888888888888888888888888888888");
    let new_repo = id("99999999999999999999999999999999");

    {
        let combined =
            BridgeStore::open_with_user_id_field(Some(state_path.clone()), UserIdField::Username)
                .expect("open combined store");
        combined
            .register_repository(RepositoryRecord {
                id: existing_repo,
                name: "ghostlore/existing".to_owned(),
                project: "ghostlore".to_owned(),
                visibility: ProjectVisibility::Internal,
                creator: "alice".to_owned(),
                created_at: 10,
            })
            .await
            .expect("register existing repo");
        combined
            .upsert_users(&[
                UserRecord {
                    id: "alice".to_owned(),
                    username: "alice".to_owned(),
                    display_name: "Alice C-Level".to_owned(),
                },
                UserRecord {
                    id: "former-dev".to_owned(),
                    username: "former-dev".to_owned(),
                    display_name: "Former Developer".to_owned(),
                },
            ])
            .await
            .expect("persist initial users in combined state");
    }

    {
        let split = BridgeStore::open_with_paths_and_field(
            Some(state_path.clone()),
            Some(user_state_path.clone()),
            UserIdField::Username,
        )
        .expect("open split store over existing combined state");
        split
            .register_repository(RepositoryRecord {
                id: new_repo,
                name: "ghostlore/dlc".to_owned(),
                project: "ghostlore".to_owned(),
                visibility: ProjectVisibility::Internal,
                creator: "alice".to_owned(),
                created_at: 20,
            })
            .await
            .expect("register second repo without user mutation");
    }

    let reopened = BridgeStore::open_with_paths_and_field(
        Some(state_path),
        Some(user_state_path),
        UserIdField::Username,
    )
    .expect("reopen split store");
    assert_eq!(reopened.find_by_username("alice").len(), 1);
    assert_eq!(reopened.find_by_username("former-dev").len(), 1);
    assert!(reopened.get_repository(existing_repo).is_some());
    assert!(reopened.get_repository(new_repo).is_some());
}

#[tokio::test]
async fn aliased_user_state_path_shares_combined_store_without_overwriting_users() {
    let dir = TempDir::new("rfs-bridge-store-alias-");
    std::fs::create_dir(dir.child("sub")).expect("create sub dir");
    let state_path = dir.child("state.json");
    let aliased_user_path = dir.path().join("sub").join("..").join("state.json");
    let repo_id = id("abababababababababababababababab");

    {
        let store = BridgeStore::open_with_paths_and_field(
            Some(state_path.clone()),
            Some(aliased_user_path),
            UserIdField::Username,
        )
        .expect("open store with lexically distinct paths to same file");
        store
            .upsert_user(UserRecord {
                id: "alice".to_owned(),
                username: "alice".to_owned(),
                display_name: "Alice C-Level".to_owned(),
            })
            .await
            .expect("upsert user before repo registration");
        store
            .register_repository(RepositoryRecord {
                id: repo_id,
                name: "ghostlore/aliased".to_owned(),
                project: "ghostlore".to_owned(),
                visibility: ProjectVisibility::Internal,
                creator: "alice".to_owned(),
                created_at: 100,
            })
            .await
            .expect("register repository on aliased combined store");
    }

    let reopened = BridgeStore::open_with_user_id_field(Some(state_path), UserIdField::Username)
        .expect("reopen combined store");
    assert!(reopened.get_repository(repo_id).is_some());
    assert_eq!(
        reopened.find_by_username("alice").len(),
        1,
        "aliased user_state_path pointing at state_path must not clobber persisted users"
    );
}

#[tokio::test]
async fn uncreated_subdir_alias_and_stale_uuid_caller_preserve_store_invariants() {
    let dir = TempDir::new("rfs-bridge-store-uncreated-alias-");
    let canon_root = std::fs::canonicalize(dir.path()).expect("canonicalize temp root");
    let state_path = dir.child("uncreated_sub").join("state.json");
    let aliased_user_path = canon_root
        .join("missing_sibling")
        .join("..")
        .join("uncreated_sub")
        .join("state.json");
    let repo_id = id("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");

    {
        let store = BridgeStore::open_with_paths_and_field(
            Some(state_path.clone()),
            Some(aliased_user_path),
            UserIdField::Username,
        )
        .expect("open store with uncreated subdir alias");
        store
            .upsert_user(UserRecord {
                id: "alice".to_owned(),
                username: "alice".to_owned(),
                display_name: "Alice C-Level".to_owned(),
            })
            .await
            .expect("upsert alice");
        store
            .register_repository(RepositoryRecord {
                id: repo_id,
                name: "ghostlore/uncreated-alias".to_owned(),
                project: "ghostlore".to_owned(),
                visibility: ProjectVisibility::Internal,
                creator: "alice".to_owned(),
                created_at: 100,
            })
            .await
            .expect("register repo");
    }

    let reopened = BridgeStore::open_with_user_id_field(Some(state_path), UserIdField::Username)
        .expect("reopen combined store");
    assert_eq!(
        reopened.find_by_username("alice").len(),
        1,
        "aliased paths inside a not-yet-created parent directory must resolve to one combined store"
    );

    let uuid_dir = TempDir::new("rfs-bridge-store-stale-caller-");
    let user_state = uuid_dir.child("users.json");
    let uuid_old = "00000000-0000-4000-8000-000000000001";
    let uuid_new = "00000000-0000-4000-8000-000000000002";
    let uuid_store =
        BridgeStore::open_with_paths_and_field(None, Some(user_state.clone()), UserIdField::Uuid)
            .expect("open uuid user store");

    uuid_store
        .upsert_user(UserRecord {
            id: uuid_old.to_owned(),
            username: "carla".to_owned(),
            display_name: "Carla Old".to_owned(),
        })
        .await
        .expect("seed old carla uuid");
    uuid_store
        .upsert_user(UserRecord {
            id: uuid_new.to_owned(),
            username: "carla".to_owned(),
            display_name: "Carla New".to_owned(),
        })
        .await
        .expect("reassign carla username to new uuid");

    uuid_store
        .upsert_caller(uuid_old, "carla", "Carla Old")
        .await
        .expect("stale caller token must not fail");
    assert_eq!(
        uuid_store.find_by_username("carla")[0].id,
        uuid_new,
        "stale login token for old UUID must not steal username reassigned to a new UUID"
    );

    let _park = rfs_lore_bridge::store::test_util::PersistPark::arm(&user_state);
    tokio::time::timeout(
        std::time::Duration::from_millis(250),
        uuid_store.upsert_caller(uuid_old, "carla", "Carla Old"),
    )
    .await
    .expect("unchanged stale caller must skip disk persistence without hitting PersistPark")
    .expect("repeat upsert_caller");

    let bad_creator_state = dir.child("bad-creator-state.json");
    std::fs::write(
        &bad_creator_state,
        r#"{
  "version": 1,
  "repositories": [
    {
      "id": "efefefefefefefefefefefefefefefef",
      "name": "ghostlore/bad-creator",
      "project": "ghostlore",
      "visibility": "internal",
      "creator": "alice\u0007control",
      "created_at": 1
    }
  ],
  "project_visibilities": {},
  "users": []
}"#,
    )
    .expect("write bad creator state");
    assert!(
        matches!(
            BridgeStore::open(Some(bad_creator_state)),
            Err(StoreError::InvalidPersistedRepository { .. })
        ),
        "persisted repository creator with control characters must be rejected"
    );

    let non_uuid_creator_state = dir.child("non-uuid-creator-state.json");
    std::fs::write(
        &non_uuid_creator_state,
        r#"{
  "version": 1,
  "repositories": [
    {
      "id": "edededededededededededededededed",
      "name": "ghostlore/non-uuid-creator",
      "project": "ghostlore",
      "visibility": "internal",
      "creator": "carla",
      "created_at": 1
    }
  ],
  "project_visibilities": {},
  "users": []
}"#,
    )
    .expect("write non-uuid creator state");
    assert!(
        matches!(
            BridgeStore::open_with_user_id_field(Some(non_uuid_creator_state), UserIdField::Uuid),
            Err(StoreError::InvalidPersistedRepository { .. })
        ),
        "persisted non-UUID creator in Uuid mode must fail fast as InvalidPersistedRepository"
    );

    let username_store =
        BridgeStore::open_with_user_id_field(None, UserIdField::Username).expect("username store");
    username_store
        .upsert_caller("bob", "carla", "Bob")
        .await
        .expect("upsert bob");
    assert!(
        username_store.find_by_username("carla").is_empty(),
        "Username mode must not let bob claim carla's username slot"
    );
    assert_eq!(username_store.find_by_username("bob")[0].id, "bob");

    let pure_oidc_uuid =
        BridgeStore::open_with_user_id_field(None, UserIdField::Uuid).expect("pure oidc store");
    pure_oidc_uuid
        .upsert_caller_with_iat(uuid_old, "carla", "Carla Old", Some(100))
        .await
        .expect("seed pure oidc old uuid");
    assert_eq!(pure_oidc_uuid.find_by_username("carla")[0].id, uuid_old);

    pure_oidc_uuid
        .upsert_caller_with_iat(uuid_new, "carla", "Carla New", Some(200))
        .await
        .expect("newer iat token claims reassigned username");
    assert_eq!(
        pure_oidc_uuid.find_by_username("carla")[0].id,
        uuid_new,
        "strictly newer OIDC iat must transfer reassigned username in pure-OIDC UUID mode"
    );

    pure_oidc_uuid
        .upsert_caller_with_iat(uuid_old, "carla", "Carla Old", Some(100))
        .await
        .expect("replayed older iat token must not fail");
    assert_eq!(
        pure_oidc_uuid.find_by_username("carla")[0].id,
        uuid_new,
        "replayed older OIDC iat must not reclaim reassigned username"
    );
}

#[tokio::test]
async fn uuid_claim_iat_survives_restart_and_elevates_when_directory_confirms_owner() {
    let dir = TempDir::new("rfs-bridge-store-claim-iat-");
    let state_path = dir.child("registry-state.json");
    let uuid_old = "00000000-0000-4000-8000-000000000701";
    let uuid_new = "00000000-0000-4000-8000-000000000702";

    {
        let store =
            BridgeStore::open_with_user_id_field(Some(state_path.clone()), UserIdField::Uuid)
                .expect("open initial uuid store");
        store
            .upsert_caller_with_iat(uuid_old, "carla", "Carla", Some(500))
            .await
            .expect("seed uuid_old with iat 500");
    }

    {
        let reopened =
            BridgeStore::open_with_user_id_field(Some(state_path.clone()), UserIdField::Uuid)
                .expect("reopen uuid store");

        reopened
            .upsert_caller_with_iat(uuid_new, "carla", "Carla", Some(400))
            .await
            .expect("older iat 400 must not fail");
        assert_eq!(
            reopened.find_by_username("carla")[0].id,
            uuid_old,
            "persisted claim_iat must still reject older iat after restart"
        );

        // Pre-restart token issued at iat=1000 (> 500, but < wall-clock `loaded_at`) must claim reassigned username.
        reopened
            .upsert_caller_with_iat(uuid_new, "carla", "Carla", Some(1000))
            .await
            .expect("newer pre-restart iat 1000");
        assert_eq!(
            reopened.find_by_username("carla")[0].id,
            uuid_new,
            "pre-restart token with iat > persisted claim_iat must claim reassigned username"
        );

        // Directory confirmation (`upsert_user`) with identical username/display_name must elevate `claim_iat` to `u64::MAX`.
        reopened
            .upsert_user(UserRecord {
                id: uuid_new.to_owned(),
                username: "carla".to_owned(),
                display_name: "Carla".to_owned(),
            })
            .await
            .expect("confirm uuid_new via directory");

        reopened
            .upsert_caller_with_iat(uuid_old, "carla", "Carla", Some(2000))
            .await
            .expect("unconfirmed OIDC claim after directory confirmation");
        assert_eq!(
            reopened.find_by_username("carla")[0].id,
            uuid_new,
            "directory-confirmed UUID owner must not be displaced by finite OIDC iat"
        );
    }

    let reopened_after_confirm =
        BridgeStore::open_with_user_id_field(Some(state_path), UserIdField::Uuid)
            .expect("reopen after directory confirm");
    reopened_after_confirm
        .upsert_caller_with_iat(uuid_old, "carla", "Carla", Some(3000))
        .await
        .expect("unconfirmed OIDC claim after second restart");
    assert_eq!(
        reopened_after_confirm.find_by_username("carla")[0].id,
        uuid_new,
        "directory-confirmed u64::MAX claim_iat must survive restart"
    );
}

#[tokio::test]
async fn refreshed_uuid_owner_advances_iat_watermark_blocking_intermediate_stale_token() {
    let store = BridgeStore::open_with_user_id_field(None, UserIdField::Uuid)
        .expect("open in-memory uuid store");
    let uuid_a = "00000000-0000-4000-8000-000000000801";
    let uuid_b = "00000000-0000-4000-8000-000000000802";

    store
        .upsert_caller_with_iat(uuid_a, "carla", "Carla", Some(100))
        .await
        .expect("seed uuid_a at iat 100");

    // Current owner refreshes login token with unchanged username/display_name at iat = 500.
    store
        .upsert_caller_with_iat(uuid_a, "carla", "Carla", Some(500))
        .await
        .expect("refresh uuid_a at iat 500");

    // Replayed intermediate token minted at iat = 300 (100 < 300 < 500) must NOT steal `carla`.
    store
        .upsert_caller_with_iat(uuid_b, "carla", "Carla B", Some(300))
        .await
        .expect("replay stale uuid_b at iat 300");

    let matches = store.find_by_username("carla");
    assert_eq!(matches.len(), 1);
    assert_eq!(
        matches[0].id, uuid_a,
        "refreshed owner watermark (iat 500) must block intermediate stale token (iat 300)"
    );
}

#[tokio::test]
async fn clear_unconfirmed_username_guards_expected_owner_and_max_claim_iat() {
    let store = BridgeStore::open_with_user_id_field(None, UserIdField::Uuid)
        .expect("open in-memory uuid store");
    let uuid_a = "00000000-0000-4000-8000-000000000901";
    let uuid_b = "00000000-0000-4000-8000-000000000902";

    store
        .upsert_caller_with_iat(uuid_a, "new_hire", "New Hire", Some(1000))
        .await
        .expect("seed uuid_a at iat 1000");

    // Wrong expected owner or lower `max_claim_iat` must leave `new_hire` intact.
    store
        .clear_unconfirmed_username("new_hire", uuid_b, 1000)
        .await
        .expect("mismatched owner clear");
    assert_eq!(store.find_by_username("new_hire").len(), 1);

    store
        .clear_unconfirmed_username("new_hire", uuid_a, 999)
        .await
        .expect("stale max_claim_iat clear");
    assert_eq!(store.find_by_username("new_hire").len(), 1);

    // Matching `(uuid_a, 1000)` clears `new_hire` and records the refuted `iat` watermark.
    store
        .clear_unconfirmed_username("new_hire", uuid_a, 1000)
        .await
        .expect("matching owner clear");
    assert!(store.find_by_username("new_hire").is_empty());

    store
        .upsert_caller_with_iat(uuid_a, "new_hire", "New Hire", Some(1000))
        .await
        .expect("replay refuted iat 1000");
    assert!(
        store.find_by_username("new_hire").is_empty(),
        "refuted_iat watermark must prevent re-seeding at <= 1000"
    );
}

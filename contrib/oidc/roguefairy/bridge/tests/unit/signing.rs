// SPDX-FileCopyrightText: 2026 Rogue Fairy Studios
// SPDX-License-Identifier: MIT

use jsonwebtoken::Algorithm;
use jsonwebtoken::Validation;
use jsonwebtoken::decode;
use jsonwebtoken::decode_header;
use lore_base::test_util::TempDir;
use rfs_lore_bridge::error::SigningError;
use rfs_lore_bridge::signing::KeyOrigin;
use rfs_lore_bridge::signing::TokenSigner;
use serde_json::json;

#[test]
fn generated_key_file_reloads_with_identical_kid_and_verifies_tokens() {
    let dir = TempDir::new("rfs-signing-key-");
    let key_path = dir.child("nested").join("signing.pk8");

    let (first, origin_first) =
        TokenSigner::load_or_generate(None, Some(&key_path)).expect("generate key file");
    assert_eq!(origin_first, KeyOrigin::GeneratedFile);

    let (reloaded, origin_reloaded) =
        TokenSigner::load_or_generate(None, Some(&key_path)).expect("reload key file");
    assert_eq!(origin_reloaded, KeyOrigin::LoadedFile);
    assert_eq!(first.kid(), reloaded.kid());

    let claims = json!({
        "iss": "https://lore-auth.roguefairy.net",
        "sub": "user-1",
        "aud": ["https://lore.roguefairy.net"],
        "iat": 1_700_000_000_u64,
        "exp": 4_102_444_800_u64,
    });
    let token = first.sign_access_token(&claims).expect("sign token");
    let header = decode_header(&token).expect("decode header");
    assert_eq!(header.alg, Algorithm::ES256);
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
    assert_eq!(header.kid.as_deref(), Some(reloaded.kid()));

    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&["https://lore.roguefairy.net"]);
    validation.set_issuer(&["https://lore-auth.roguefairy.net"]);
    let verified = decode::<serde_json::Value>(&token, reloaded.decoding_key(), &validation)
        .expect("verify with reloaded key");
    assert_eq!(verified.claims["sub"], "user-1");
}

#[test]
fn base64_key_round_trips_and_rejects_corrupt_bytes() {
    let encoded = TokenSigner::generate_base64_pkcs8().expect("generate base64 key");
    let (_, origin) = TokenSigner::load_or_generate(Some(&encoded), None).expect("load base64 key");
    assert_eq!(origin, KeyOrigin::Environment);

    let err = TokenSigner::from_pkcs8_der(b"not-valid-pkcs8").err();
    assert!(matches!(err, Some(SigningError::InvalidPkcs8Key)));
}

#[test]
fn unreadable_or_invalid_key_path_returns_read_error_without_overwriting() {
    let invalid_path = std::path::Path::new("bad\0signing.pk8");
    let err = TokenSigner::load_or_generate(None, Some(invalid_path)).err();
    assert!(
        matches!(err, Some(SigningError::ReadKeyFile { .. })),
        "non-NotFound stat/read failure must return ReadKeyFile, not overwrite via WriteKeyFile: {err:?}"
    );
}

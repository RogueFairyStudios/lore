// SPDX-FileCopyrightText: 2026 Rogue Fairy Studios
// SPDX-License-Identifier: MIT

use std::path::Path;
use std::sync::Arc;

use axum::body::Bytes;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::jwk::Jwk;
use ring::rand::SystemRandom;
use ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
use ring::signature::EcdsaKeyPair;
use ring::signature::KeyPair as _;
use serde::Serialize;
use serde_json::json;

use crate::error::SigningError;

const UNCOMPRESSED_P256_PUBLIC_KEY_LEN: usize = 65;
const UNCOMPRESSED_POINT_TAG: u8 = 0x04;
const ACCESS_TOKEN_TYP: &str = "at+jwt";
const ES256_UNPADDED_SIGNATURE_B64_LEN: usize = 86;

/// ECDSA P-256 (`ES256`) signer and verifier for partition-scoped access tokens.
#[derive(Clone)]
pub struct TokenSigner {
    kid: Arc<str>,
    encoded_header_prefix: Arc<str>,
    key_pair: Arc<EcdsaKeyPair>,
    rng: SystemRandom,
    decoding_key: DecodingKey,
    jwks_bytes: Bytes,
}

impl TokenSigner {
    /// Loads a P-256 PKCS#8 key from base64, from disk (generating and saving
    /// one when the file is absent), or generates an ephemeral key in memory.
    pub fn load_or_generate(
        signing_key_b64: Option<&str>,
        signing_key_path: Option<&Path>,
    ) -> Result<(Self, KeyOrigin), SigningError> {
        if let Some(encoded) = signing_key_b64 {
            let trimmed = encoded.trim();
            let der = STANDARD
                .decode(trimmed)
                .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed))?;
            return Ok((Self::from_pkcs8_der(&der)?, KeyOrigin::Environment));
        }

        if let Some(path) = signing_key_path {
            match std::fs::read(path) {
                Ok(der) => return Ok((Self::from_pkcs8_der(&der)?, KeyOrigin::LoadedFile)),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    let der = generate_p256_pkcs8()?;
                    write_key_file_atomic(path, &der)?;
                    return Ok((Self::from_pkcs8_der(&der)?, KeyOrigin::GeneratedFile));
                }
                Err(source) => {
                    return Err(SigningError::ReadKeyFile {
                        path: path.to_path_buf(),
                        source,
                    });
                }
            }
        }

        let der = generate_p256_pkcs8()?;
        Ok((Self::from_pkcs8_der(&der)?, KeyOrigin::Ephemeral))
    }

    /// Builds a signer directly from PKCS#8 v1 DER P-256 private key bytes.
    pub fn from_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self, SigningError> {
        let rng = SystemRandom::new();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_der, &rng)
            .map_err(|_err| SigningError::InvalidPkcs8Key)?;
        let public_bytes = pair.public_key().as_ref();
        if public_bytes.len() != UNCOMPRESSED_P256_PUBLIC_KEY_LEN
            || public_bytes[0] != UNCOMPRESSED_POINT_TAG
        {
            return Err(SigningError::InvalidPublicKeyPoint);
        }

        let x = URL_SAFE_NO_PAD.encode(&public_bytes[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&public_bytes[33..65]);
        let digest = blake3::hash(public_bytes);
        let kid: Arc<str> = Arc::from(format!("rfs-{}", hex::encode(&digest.as_bytes()[..8])));

        let jwk_json = json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "use": "sig",
            "kid": &*kid,
            "x": x,
            "y": y,
        });
        let jwk: Jwk = serde_json::from_value(jwk_json.clone())
            .map_err(|_err| SigningError::InvalidPkcs8Key)?;
        let decoding_key = DecodingKey::from_jwk(&jwk)?;
        let jwks_bytes = Bytes::from(
            serde_json::to_vec(&json!({ "keys": [jwk_json] }))
                .map_err(|_err| SigningError::InvalidPkcs8Key)?,
        );
        let header_bytes = serde_json::to_vec(&json!({
            "typ": ACCESS_TOKEN_TYP,
            "alg": "ES256",
            "kid": &*kid,
        }))
        .map_err(|_err| SigningError::InvalidPkcs8Key)?;
        let encoded_header_prefix: Arc<str> =
            Arc::from(format!("{}.", URL_SAFE_NO_PAD.encode(&header_bytes)));

        Ok(Self {
            kid,
            encoded_header_prefix,
            key_pair: Arc::new(pair),
            rng,
            decoding_key,
            jwks_bytes,
        })
    }

    /// Generates a new PKCS#8 v1 DER P-256 keypair encoded as standard base64.
    pub fn generate_base64_pkcs8() -> Result<String, SigningError> {
        let der = generate_p256_pkcs8()?;
        Ok(STANDARD.encode(der))
    }

    /// Returns the deterministic key identifier derived from the public key.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Returns the `DecodingKey` matching this signer's public key.
    #[lore_macro::test_pub]
    pub(crate) fn decoding_key(&self) -> &DecodingKey {
        &self.decoding_key
    }

    /// Returns the pre-serialized UTF-8 JSON bytes served at `/jwks`.
    pub fn jwks_bytes(&self) -> Bytes {
        self.jwks_bytes.clone()
    }

    /// Signs `claims` as an RFC 9068 `at+jwt` `ES256` token using the pre-parsed keypair and header.
    pub fn sign_access_token<T: Serialize>(&self, claims: &T) -> Result<String, SigningError> {
        let claims_bytes = serde_json::to_vec(claims)?;
        let payload_b64_len = claims_bytes.len().div_ceil(3) * 4;
        let mut token = String::with_capacity(
            self.encoded_header_prefix.len()
                + payload_b64_len
                + 1
                + ES256_UNPADDED_SIGNATURE_B64_LEN,
        );
        token.push_str(&self.encoded_header_prefix);
        URL_SAFE_NO_PAD.encode_string(&claims_bytes, &mut token);
        let signature = self
            .key_pair
            .sign(&self.rng, token.as_bytes())
            .map_err(|_err| SigningError::SignFailed)?;
        token.push('.');
        URL_SAFE_NO_PAD.encode_string(signature.as_ref(), &mut token);
        Ok(token)
    }
}

/// Where the active `TokenSigner` key material originated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyOrigin {
    Environment,
    LoadedFile,
    GeneratedFile,
    Ephemeral,
}

fn generate_p256_pkcs8() -> Result<Vec<u8>, SigningError> {
    let rng = SystemRandom::new();
    let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .map_err(|_err| SigningError::KeyGeneration)?;
    Ok(document.as_ref().to_vec())
}

fn write_key_file_atomic(path: &Path, pkcs8_der: &[u8]) -> Result<(), SigningError> {
    crate::store::write_file_atomic_0600(
        path,
        |failed_path, source| SigningError::WriteKeyFile {
            path: failed_path,
            source,
        },
        |file, tmp_path| {
            std::io::Write::write_all(file, pkcs8_der).map_err(|source| {
                SigningError::WriteKeyFile {
                    path: tmp_path.to_path_buf(),
                    source,
                }
            })
        },
    )
}

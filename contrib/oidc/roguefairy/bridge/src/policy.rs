// SPDX-FileCopyrightText: 2026 Rogue Fairy Studios
// SPDX-License-Identifier: MIT

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::str::FromStr;

use lore_base::types::Context;
use lore_base::types::RepositoryId;
use serde::Deserialize;
use serde::Serialize;
use serde_with::OneOrMany;
use serde_with::formats::PreferMany;
use serde_with::serde_as;

use crate::config::PolicyConfig;
use crate::config::StaticProjectConfig;
use crate::config::UserIdField;
use crate::error::AuthVerifyError;
use crate::error::PolicyError;
use crate::store::RepositoryRecord;

pub const GROUP_C_LEVEL: &str = "Rogue Fairy Studios - C-Level";
pub const GROUP_AUTHENTIK_ADMINS: &str = "authentik Admins";
pub const GROUP_EMPLOYEES: &str = "Rogue Fairy Studios";
pub const GROUP_PARTNERS: &str = "Rogue Fairy Studios - Partners";
pub const DEFAULT_CLAIMS_KEY: &str = "rfs_lore";

const MAX_REPOSITORY_NAME_BYTES: usize = 1000;
pub(crate) const MAX_PROJECT_SLUG_BYTES: usize = 64;

/// Canonical Lore repository actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LoreAction {
    Read,
    Write,
    Owner,
    Admin,
    Migrate,
    PushProtected,
    Obliterate,
    Presign,
}

impl LoreAction {
    pub const ALL: [Self; 8] = [
        Self::Read,
        Self::Write,
        Self::Owner,
        Self::Admin,
        Self::Migrate,
        Self::PushProtected,
        Self::Obliterate,
        Self::Presign,
    ];

    /// Returns the wire action name expected by Lore Server.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Migrate => "migrate",
            Self::PushProtected => "push-protected",
            Self::Obliterate => "obliterate",
            Self::Presign => "presign",
        }
    }

    /// Parses a wire action name into [`LoreAction`].
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "owner" => Some(Self::Owner),
            "admin" => Some(Self::Admin),
            "migrate" => Some(Self::Migrate),
            "push-protected" => Some(Self::PushProtected),
            "obliterate" => Some(Self::Obliterate),
            "presign" => Some(Self::Presign),
            _ => None,
        }
    }

    const fn bit(self) -> u8 {
        match self {
            Self::Read => 1 << 0,
            Self::Write => 1 << 1,
            Self::Owner => 1 << 2,
            Self::Admin => 1 << 3,
            Self::Migrate => 1 << 4,
            Self::PushProtected => 1 << 5,
            Self::Obliterate => 1 << 6,
            Self::Presign => 1 << 7,
        }
    }
}

/// Bitmask of [`LoreAction`] values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActionSet(u8);

impl ActionSet {
    pub const EMPTY: Self = Self(0);
    pub const ALL: Self = Self(0xFF);

    /// Returns whether no actions are present in the set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns the number of actions present in the set.
    pub const fn len(self) -> usize {
        self.0.count_ones() as usize
    }

    /// Returns whether `action` is present in the set.
    pub const fn contains(self, action: LoreAction) -> bool {
        (self.0 & action.bit()) != 0
    }

    /// Inserts `action` into the set.
    pub const fn insert(&mut self, action: LoreAction) {
        self.0 |= action.bit();
    }

    /// Returns the union of `self` and `other`.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Iterates over every action present in canonical [`LoreAction::ALL`] order.
    pub fn iter(self) -> impl Iterator<Item = LoreAction> {
        LoreAction::ALL
            .into_iter()
            .filter(move |&action| self.contains(action))
    }

    /// Writes the wire names of all actions in the set into `out` without heap allocation.
    pub fn write_static_strs<'a>(self, out: &'a mut [&'static str; 8]) -> &'a [&'static str] {
        let mut count = 0;
        for action in LoreAction::ALL {
            if self.contains(action) {
                out[count] = action.as_str();
                count += 1;
            }
        }
        &out[..count]
    }

    /// Builds an [`ActionSet`] containing all actions in `actions`.
    pub const fn from_slice(actions: &[LoreAction]) -> Self {
        let mut set = Self::EMPTY;
        let mut idx = 0;
        while idx < actions.len() {
            set.insert(actions[idx]);
            idx += 1;
        }
        set
    }

    /// Collects owned wire names of all actions in the set for protobuf responses.
    pub fn to_permission_strings(self) -> Vec<String> {
        let mut perms = Vec::with_capacity(self.len());
        for action in self.iter() {
            perms.push(action.as_str().to_owned());
        }
        perms
    }
}

impl<'de> Deserialize<'de> for ActionSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ActionSetVisitor;

        impl<'de> serde::de::Visitor<'de> for ActionSetVisitor {
            type Value = ActionSet;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON array of Lore action strings")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut set = ActionSet::EMPTY;
                while let Some(raw) = seq.next_element::<Cow<'de, str>>()? {
                    if let Some(parsed) = LoreAction::parse(raw.as_ref()) {
                        set.insert(parsed);
                    }
                }
                Ok(set)
            }
        }

        deserializer.deserialize_seq(ActionSetVisitor)
    }
}

/// Project visibility for baseline studio employee access.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProjectVisibility {
    /// Accessible (`read` and `write`) to members of `Rogue Fairy Studios`,
    /// while external partners still need an explicit project group.
    #[default]
    Internal,
    /// Accessible only to `C-Level`, `authentik Admins`, and callers carrying
    /// an explicit grant for this project.
    Restricted,
}

impl ProjectVisibility {
    /// Combines two visibilities, keeping `Restricted` whenever either requires it.
    pub const fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Self::Restricted, _) | (_, Self::Restricted) => Self::Restricted,
            (Self::Internal, Self::Internal) => Self::Internal,
        }
    }
}

/// Per-project permissions carried by a caller's login token.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProjectGrant {
    pub actions: ActionSet,
    pub can_create_repo: bool,
    pub visibility: ProjectVisibility,
}

/// Evaluated authorization profile of a verified login token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallerClaims {
    pub sub: String,
    pub identity: String,
    pub username: String,
    pub display_name: String,
    pub is_service_account: bool,
    pub token_iat: Option<u64>,
    pub exp: u64,
    pub is_c_level: bool,
    pub is_employee: bool,
    pub is_partner: bool,
    pub can_create_any: bool,
    pub global_actions: ActionSet,
    pub projects: BTreeMap<String, ProjectGrant>,
}

/// Resource entry inside an exchanged `at+jwt` token.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ResourceGrantClaim {
    pub resource_id: String,
    pub permission: Vec<String>,
}

/// Borrowed resource entry used when signing exchanged `at+jwt` tokens without string copies.
#[derive(Serialize)]
pub struct BorrowedResourceGrantClaim<'a> {
    pub resource_id: &'a str,
    pub permission: &'a [&'static str],
}

/// Claims issued by `rfs-lore-bridge` on exchanged `at+jwt` tokens.
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ExchangedTokenClaims {
    pub iss: String,
    pub sub: String,
    pub identity: String,
    #[serde_as(as = "OneOrMany<_, PreferMany>")]
    pub aud: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub root_domains: Vec<String>,
    pub iat: u64,
    pub exp: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub preferred_username: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default)]
    pub is_service_account: bool,
    pub resources: Vec<ResourceGrantClaim>,
}

/// Borrowed view matching [`ExchangedTokenClaims`] wire JSON for signing on `/token`.
#[derive(Serialize)]
pub struct BorrowedExchangedTokenClaims<'a> {
    pub iss: &'a str,
    pub sub: &'a str,
    pub identity: &'a str,
    pub aud: [&'a str; 1],
    #[serde(skip_serializing_if = "slice_is_empty")]
    pub root_domains: &'a [String],
    pub iat: u64,
    pub exp: u64,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub preferred_username: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub name: &'a str,
    pub is_service_account: bool,
    pub resources: [BorrowedResourceGrantClaim<'a>; 1],
}

const fn slice_is_empty<T>(slice: &[T]) -> bool {
    slice.is_empty()
}

/// Compact verified claims extracted from a Bridge-signed `at+jwt` access token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedExchangedCaller {
    pub identity: String,
    pub repository_id: RepositoryId,
    pub actions: ActionSet,
}

/// Verified caller presented to gRPC registry and directory endpoints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifiedCaller {
    Login(Box<CallerClaims>),
    Exchanged(VerifiedExchangedCaller),
}

impl VerifiedCaller {
    /// Returns the durable Lore identity of the caller.
    pub fn identity(&self) -> &str {
        match self {
            Self::Login(claims) => &claims.identity,
            Self::Exchanged(claims) => &claims.identity,
        }
    }
}

fn deserialize_claim_visibility<'de, D>(deserializer: D) -> Result<ProjectVisibility, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<Cow<'de, str>>::deserialize(deserializer)?;
    Ok(parse_claim_visibility(opt.as_deref()))
}

/// Raw `rfs_lore.projects.<slug>` payload emitted by the `authentik` scope mapping.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct RawRfsProjectClaim {
    #[serde(default)]
    pub actions: ActionSet,
    #[serde(default)]
    pub can_create_repo: bool,
    #[serde(default, deserialize_with = "deserialize_claim_visibility")]
    pub visibility: ProjectVisibility,
}

/// Raw `rfs_lore` payload emitted by the `authentik` scope mapping.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct RawRfsLoreClaim {
    #[serde(default)]
    pub is_c_level: bool,
    #[serde(default)]
    pub is_employee: bool,
    #[serde(default)]
    pub is_partner: bool,
    #[serde(default)]
    pub can_create_any: bool,
    #[serde(default)]
    pub global_actions: ActionSet,
    #[serde(default)]
    pub projects: BTreeMap<String, RawRfsProjectClaim>,
}

/// String-valued JSON claim that distinguishes an omitted field (`None`) from a present
/// empty or non-string field (`Some(PresentStringClaim::Invalid)`) without allocating a
/// recursive JSON tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PresentStringClaim {
    Valid(String),
    Invalid,
}

impl<'de> Deserialize<'de> for PresentStringClaim {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PresentStringVisitor;

        impl<'de> serde::de::Visitor<'de> for PresentStringVisitor {
            type Value = PresentStringClaim;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("any JSON value")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                if v.is_empty() {
                    Ok(PresentStringClaim::Invalid)
                } else {
                    Ok(PresentStringClaim::Valid(v.to_owned()))
                }
            }

            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                if v.is_empty() {
                    Ok(PresentStringClaim::Invalid)
                } else {
                    Ok(PresentStringClaim::Valid(v))
                }
            }

            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
                Ok(PresentStringClaim::Invalid)
            }

            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
                Ok(PresentStringClaim::Invalid)
            }

            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
                Ok(PresentStringClaim::Invalid)
            }

            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
                Ok(PresentStringClaim::Invalid)
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(PresentStringClaim::Invalid)
            }

            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(PresentStringClaim::Invalid)
            }

            fn visit_some<D2>(self, deserializer: D2) -> Result<Self::Value, D2::Error>
            where
                D2: serde::Deserializer<'de>,
            {
                deserializer.deserialize_any(self)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                Ok(PresentStringClaim::Invalid)
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                while map
                    .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                    .is_some()
                {}
                Ok(PresentStringClaim::Invalid)
            }
        }

        deserializer.deserialize_any(PresentStringVisitor)
    }
}

/// Deserializes an optional JSON claim into `Some(PresentStringClaim)` when the field is present.
pub(crate) fn present_string_claim<'de, D>(
    deserializer: D,
) -> Result<Option<PresentStringClaim>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    PresentStringClaim::deserialize(deserializer).map(Some)
}

/// Raw OIDC login token claims verified from `authentik`.
#[derive(Clone, Debug, Deserialize)]
pub struct RawLoginClaims {
    pub sub: String,
    pub exp: u64,
    #[serde(default)]
    pub nbf: Option<u64>,
    #[serde(default)]
    pub iat: Option<u64>,
    #[serde(default, deserialize_with = "present_string_claim")]
    pub identity: Option<PresentStringClaim>,
    #[serde(
        rename = "https://lore.org/claims/identity",
        default,
        deserialize_with = "present_string_claim"
    )]
    pub identity_namespaced: Option<PresentStringClaim>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub is_service_account: Option<bool>,
    #[serde(default)]
    pub groups: Option<Vec<String>>,
    #[serde(default)]
    pub rfs_lore: Option<RawRfsLoreClaim>,
}

struct AudienceMatchSeed<'a> {
    expected: &'a [String],
}

impl<'de> serde::de::DeserializeSeed<'de> for AudienceMatchSeed<'_> {
    type Value = bool;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct AudienceMatchVisitor<'a> {
            expected: &'a [String],
        }

        impl<'de> serde::de::Visitor<'de> for AudienceMatchVisitor<'_> {
            type Value = bool;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON audience string or array of audience strings")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(self.expected.iter().any(|exp| exp == v))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut matched = false;
                while let Some(elem) = seq.next_element::<Cow<'de, str>>()? {
                    if !matched && self.expected.iter().any(|exp| exp == elem.as_ref()) {
                        matched = true;
                    }
                }
                Ok(matched)
            }
        }

        deserializer.deserialize_any(AudienceMatchVisitor {
            expected: self.expected,
        })
    }
}

struct LoginClaimsSeed<'a> {
    claims_key: &'a str,
    expected_issuer: &'a str,
    expected_audiences: &'a [String],
}

impl<'de> serde::de::DeserializeSeed<'de> for LoginClaimsSeed<'_> {
    type Value = RawLoginClaims;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct LoginClaimsVisitor<'a> {
            claims_key: &'a str,
            expected_issuer: &'a str,
            expected_audiences: &'a [String],
        }

        impl<'de> serde::de::Visitor<'de> for LoginClaimsVisitor<'_> {
            type Value = RawLoginClaims;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON object containing OIDC login claims")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut seen_iss = false;
                let mut sub: Option<String> = None;
                let mut seen_aud = false;
                let mut exp: Option<u64> = None;
                let mut nbf: Option<u64> = None;
                let mut seen_nbf = false;
                let mut iat: Option<u64> = None;
                let mut seen_iat = false;
                let mut identity: Option<PresentStringClaim> = None;
                let mut identity_namespaced: Option<PresentStringClaim> = None;
                let mut preferred_username: Option<String> = None;
                let mut seen_preferred_username = false;
                let mut name: Option<String> = None;
                let mut seen_name = false;
                let mut is_service_account: Option<bool> = None;
                let mut seen_is_service_account = false;
                let mut groups: Option<Vec<String>> = None;
                let mut seen_groups = false;
                let mut rfs_lore: Option<RawRfsLoreClaim> = None;
                let mut seen_rfs_lore = false;

                while let Some(key) = map.next_key::<Cow<'de, str>>()? {
                    match key.as_ref() {
                        "iss" => {
                            if seen_iss {
                                return Err(serde::de::Error::duplicate_field("iss"));
                            }
                            seen_iss = true;
                            let iss_val = map.next_value::<Cow<'de, str>>()?;
                            if iss_val.as_ref() != self.expected_issuer {
                                return Err(serde::de::Error::custom(
                                    "login token issuer mismatch",
                                ));
                            }
                        }
                        "sub" => {
                            if sub.is_some() {
                                return Err(serde::de::Error::duplicate_field("sub"));
                            }
                            sub = Some(map.next_value()?);
                        }
                        "aud" => {
                            if seen_aud {
                                return Err(serde::de::Error::duplicate_field("aud"));
                            }
                            seen_aud = true;
                            let matched = map.next_value_seed(AudienceMatchSeed {
                                expected: self.expected_audiences,
                            })?;
                            if !matched {
                                return Err(serde::de::Error::custom(
                                    "login token audience mismatch",
                                ));
                            }
                        }
                        "exp" => {
                            if exp.is_some() {
                                return Err(serde::de::Error::duplicate_field("exp"));
                            }
                            exp = Some(map.next_value()?);
                        }
                        "nbf" => {
                            if seen_nbf {
                                return Err(serde::de::Error::duplicate_field("nbf"));
                            }
                            seen_nbf = true;
                            nbf = map.next_value()?;
                        }
                        "iat" => {
                            if seen_iat {
                                return Err(serde::de::Error::duplicate_field("iat"));
                            }
                            seen_iat = true;
                            iat = map.next_value()?;
                        }
                        "identity" => {
                            if identity.is_some() {
                                return Err(serde::de::Error::duplicate_field("identity"));
                            }
                            identity = Some(map.next_value()?);
                        }
                        "https://lore.org/claims/identity" => {
                            if identity_namespaced.is_some() {
                                return Err(serde::de::Error::duplicate_field(
                                    "https://lore.org/claims/identity",
                                ));
                            }
                            identity_namespaced = Some(map.next_value()?);
                        }
                        "preferred_username" => {
                            if seen_preferred_username {
                                return Err(serde::de::Error::duplicate_field(
                                    "preferred_username",
                                ));
                            }
                            seen_preferred_username = true;
                            preferred_username = map.next_value()?;
                        }
                        "name" => {
                            if seen_name {
                                return Err(serde::de::Error::duplicate_field("name"));
                            }
                            seen_name = true;
                            name = map.next_value()?;
                        }
                        "is_service_account" => {
                            if seen_is_service_account {
                                return Err(serde::de::Error::duplicate_field(
                                    "is_service_account",
                                ));
                            }
                            seen_is_service_account = true;
                            is_service_account = map.next_value()?;
                        }
                        "groups" => {
                            if seen_groups {
                                return Err(serde::de::Error::duplicate_field("groups"));
                            }
                            seen_groups = true;
                            groups = map.next_value()?;
                        }
                        other if other == self.claims_key => {
                            if seen_rfs_lore {
                                return Err(serde::de::Error::custom(
                                    "duplicate policy claims_key field",
                                ));
                            }
                            seen_rfs_lore = true;
                            rfs_lore = map.next_value()?;
                        }
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }

                if !seen_iss {
                    return Err(serde::de::Error::missing_field("iss"));
                }
                if !seen_aud {
                    return Err(serde::de::Error::missing_field("aud"));
                }

                Ok(RawLoginClaims {
                    sub: sub.ok_or_else(|| serde::de::Error::missing_field("sub"))?,
                    exp: exp.ok_or_else(|| serde::de::Error::missing_field("exp"))?,
                    nbf,
                    iat,
                    identity,
                    identity_namespaced,
                    preferred_username,
                    name,
                    is_service_account,
                    groups,
                    rfs_lore,
                })
            }
        }

        deserializer.deserialize_map(LoginClaimsVisitor {
            claims_key: self.claims_key,
            expected_issuer: self.expected_issuer,
            expected_audiences: self.expected_audiences,
        })
    }
}

/// Deserializes and validates [`RawLoginClaims`] (`iss`, `aud`, `exp`, `nbf`) from a verified JWT
/// payload in a single pass without allocating unused issuer or audience collections.
pub(crate) fn deserialize_and_validate_login_claims(
    payload_bytes: &[u8],
    claims_key: &str,
    expected_issuer: &str,
    expected_audiences: &[String],
    now_secs: u64,
    leeway_secs: u64,
) -> Result<RawLoginClaims, ()> {
    use serde::de::DeserializeSeed as _;

    let mut de = serde_json::Deserializer::from_slice(payload_bytes);
    let claims = LoginClaimsSeed {
        claims_key,
        expected_issuer,
        expected_audiences,
    }
    .deserialize(&mut de)
    .map_err(|_err| ())?;
    de.end().map_err(|_err| ())?;

    if now_secs.saturating_sub(leeway_secs) > claims.exp {
        return Err(());
    }
    if let Some(nbf) = claims.nbf
        && nbf > now_secs.saturating_add(leeway_secs)
    {
        return Err(());
    }
    Ok(claims)
}

struct StrictActionsSeed;

impl<'de> serde::de::DeserializeSeed<'de> for StrictActionsSeed {
    type Value = ActionSet;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StrictActionsVisitor;

        impl<'de> serde::de::Visitor<'de> for StrictActionsVisitor {
            type Value = ActionSet;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a non-empty JSON array of valid Lore action strings")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut set = ActionSet::EMPTY;
                while let Some(raw) = seq.next_element::<Cow<'de, str>>()? {
                    let parsed = LoreAction::parse(raw.as_ref())
                        .ok_or_else(|| serde::de::Error::custom("unknown Lore permission"))?;
                    set.insert(parsed);
                }
                if set.is_empty() {
                    return Err(serde::de::Error::custom("empty permission array"));
                }
                Ok(set)
            }
        }

        deserializer.deserialize_seq(StrictActionsVisitor)
    }
}

struct SingleResourceSeed<'a> {
    resource_id_template: &'a str,
}

impl<'de> serde::de::DeserializeSeed<'de> for SingleResourceSeed<'_> {
    type Value = (RepositoryId, ActionSet);

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SingleResourceSeqVisitor<'a> {
            resource_id_template: &'a str,
        }

        impl<'de> serde::de::Visitor<'de> for SingleResourceSeqVisitor<'_> {
            type Value = (RepositoryId, ActionSet);

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a single-element resources array")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let first = seq
                    .next_element_seed(ResourceEntrySeed {
                        resource_id_template: self.resource_id_template,
                    })?
                    .ok_or_else(|| serde::de::Error::custom("missing resource entry"))?;
                if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::custom(
                        "exchanged token must carry a single resource",
                    ));
                }
                Ok(first)
            }
        }

        struct ResourceEntrySeed<'a> {
            resource_id_template: &'a str,
        }

        impl<'de> serde::de::DeserializeSeed<'de> for ResourceEntrySeed<'_> {
            type Value = (RepositoryId, ActionSet);

            fn deserialize<D2>(self, deserializer: D2) -> Result<Self::Value, D2::Error>
            where
                D2: serde::Deserializer<'de>,
            {
                struct ResourceEntryVisitor<'a> {
                    resource_id_template: &'a str,
                }

                impl<'de> serde::de::Visitor<'de> for ResourceEntryVisitor<'_> {
                    type Value = (RepositoryId, ActionSet);

                    fn expecting(
                        &self,
                        formatter: &mut std::fmt::Formatter<'_>,
                    ) -> std::fmt::Result {
                        formatter.write_str("a resource grant object")
                    }

                    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
                    where
                        M: serde::de::MapAccess<'de>,
                    {
                        let mut repository_id: Option<RepositoryId> = None;
                        let mut actions: Option<ActionSet> = None;

                        while let Some(key) = map.next_key::<Cow<'de, str>>()? {
                            match key.as_ref() {
                                "resource_id" => {
                                    if repository_id.is_some() {
                                        return Err(serde::de::Error::duplicate_field(
                                            "resource_id",
                                        ));
                                    }
                                    let raw_id = map.next_value::<Cow<'de, str>>()?;
                                    let parsed = parse_resource_claim_id(
                                        raw_id.as_ref(),
                                        self.resource_id_template,
                                    )
                                    .ok_or_else(|| {
                                        serde::de::Error::custom("invalid resource_id")
                                    })?;
                                    repository_id = Some(parsed);
                                }
                                "permission" => {
                                    if actions.is_some() {
                                        return Err(serde::de::Error::duplicate_field(
                                            "permission",
                                        ));
                                    }
                                    actions = Some(map.next_value_seed(StrictActionsSeed)?);
                                }
                                _ => {
                                    let _: serde::de::IgnoredAny = map.next_value()?;
                                }
                            }
                        }

                        Ok((
                            repository_id
                                .ok_or_else(|| serde::de::Error::missing_field("resource_id"))?,
                            actions.ok_or_else(|| serde::de::Error::missing_field("permission"))?,
                        ))
                    }
                }

                deserializer.deserialize_map(ResourceEntryVisitor {
                    resource_id_template: self.resource_id_template,
                })
            }
        }

        deserializer.deserialize_seq(SingleResourceSeqVisitor {
            resource_id_template: self.resource_id_template,
        })
    }
}

struct ExchangedClaimsSeed<'a> {
    expected_issuer: &'a str,
    expected_audience: &'a [String],
    resource_id_template: &'a str,
}

struct ParsedExchangedPayload {
    sub_non_empty: bool,
    identity: String,
    exp: u64,
    nbf: Option<u64>,
    repository_id: RepositoryId,
    actions: ActionSet,
}

impl<'de> serde::de::DeserializeSeed<'de> for ExchangedClaimsSeed<'_> {
    type Value = ParsedExchangedPayload;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ExchangedClaimsVisitor<'a> {
            expected_issuer: &'a str,
            expected_audience: &'a [String],
            resource_id_template: &'a str,
        }

        impl<'de> serde::de::Visitor<'de> for ExchangedClaimsVisitor<'_> {
            type Value = ParsedExchangedPayload;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON object containing exchanged at+jwt claims")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut seen_iss = false;
                let mut sub_non_empty: Option<bool> = None;
                let mut identity: Option<String> = None;
                let mut seen_aud = false;
                let mut seen_iat = false;
                let mut exp: Option<u64> = None;
                let mut nbf: Option<u64> = None;
                let mut seen_nbf = false;
                let mut seen_is_service_account = false;
                let mut resource_grant: Option<(RepositoryId, ActionSet)> = None;

                while let Some(key) = map.next_key::<Cow<'de, str>>()? {
                    match key.as_ref() {
                        "iss" => {
                            if seen_iss {
                                return Err(serde::de::Error::duplicate_field("iss"));
                            }
                            seen_iss = true;
                            let val = map.next_value::<Cow<'de, str>>()?;
                            if val.as_ref() != self.expected_issuer {
                                return Err(serde::de::Error::custom(
                                    "exchanged token issuer mismatch",
                                ));
                            }
                        }
                        "sub" => {
                            if sub_non_empty.is_some() {
                                return Err(serde::de::Error::duplicate_field("sub"));
                            }
                            let val = map.next_value::<Cow<'de, str>>()?;
                            sub_non_empty = Some(!val.is_empty());
                        }
                        "identity" => {
                            if identity.is_some() {
                                return Err(serde::de::Error::duplicate_field("identity"));
                            }
                            identity = Some(map.next_value()?);
                        }
                        "aud" => {
                            if seen_aud {
                                return Err(serde::de::Error::duplicate_field("aud"));
                            }
                            seen_aud = true;
                            let matched = map.next_value_seed(AudienceMatchSeed {
                                expected: self.expected_audience,
                            })?;
                            if !matched {
                                return Err(serde::de::Error::custom(
                                    "exchanged token audience mismatch",
                                ));
                            }
                        }
                        "iat" => {
                            if seen_iat {
                                return Err(serde::de::Error::duplicate_field("iat"));
                            }
                            seen_iat = true;
                            let _: u64 = map.next_value()?;
                        }
                        "exp" => {
                            if exp.is_some() {
                                return Err(serde::de::Error::duplicate_field("exp"));
                            }
                            exp = Some(map.next_value()?);
                        }
                        "nbf" => {
                            if seen_nbf {
                                return Err(serde::de::Error::duplicate_field("nbf"));
                            }
                            seen_nbf = true;
                            nbf = map.next_value()?;
                        }
                        "is_service_account" => {
                            if seen_is_service_account {
                                return Err(serde::de::Error::duplicate_field(
                                    "is_service_account",
                                ));
                            }
                            seen_is_service_account = true;
                            let _: bool = map.next_value()?;
                        }
                        "resources" => {
                            if resource_grant.is_some() {
                                return Err(serde::de::Error::duplicate_field("resources"));
                            }
                            resource_grant = Some(map.next_value_seed(SingleResourceSeed {
                                resource_id_template: self.resource_id_template,
                            })?);
                        }
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }

                if !seen_iss {
                    return Err(serde::de::Error::missing_field("iss"));
                }
                if !seen_aud {
                    return Err(serde::de::Error::missing_field("aud"));
                }
                if !seen_iat {
                    return Err(serde::de::Error::missing_field("iat"));
                }
                let (repository_id, actions) =
                    resource_grant.ok_or_else(|| serde::de::Error::missing_field("resources"))?;

                Ok(ParsedExchangedPayload {
                    sub_non_empty: sub_non_empty
                        .ok_or_else(|| serde::de::Error::missing_field("sub"))?,
                    identity: identity
                        .ok_or_else(|| serde::de::Error::missing_field("identity"))?,
                    exp: exp.ok_or_else(|| serde::de::Error::missing_field("exp"))?,
                    nbf,
                    repository_id,
                    actions,
                })
            }
        }

        deserializer.deserialize_map(ExchangedClaimsVisitor {
            expected_issuer: self.expected_issuer,
            expected_audience: self.expected_audience,
            resource_id_template: self.resource_id_template,
        })
    }
}

/// Deserializes and validates a verified `at+jwt` payload directly into [`VerifiedExchangedCaller`]
/// without allocating unused claims or re-parsing resource permissions downstream.
pub(crate) fn deserialize_and_validate_exchanged_claims(
    payload_bytes: &[u8],
    expected_issuer: &str,
    expected_audience: &[String],
    resource_id_template: &str,
    user_id_field: UserIdField,
    now_secs: u64,
    leeway_secs: u64,
) -> Result<VerifiedExchangedCaller, AuthVerifyError> {
    use serde::de::DeserializeSeed as _;

    let mut de = serde_json::Deserializer::from_slice(payload_bytes);
    let parsed = ExchangedClaimsSeed {
        expected_issuer,
        expected_audience,
        resource_id_template,
    }
    .deserialize(&mut de)
    .map_err(|_err| AuthVerifyError::InvalidToken)?;
    de.end().map_err(|_err| AuthVerifyError::InvalidToken)?;

    if now_secs.saturating_sub(leeway_secs) > parsed.exp {
        return Err(AuthVerifyError::InvalidToken);
    }
    if let Some(nbf) = parsed.nbf
        && nbf > now_secs.saturating_add(leeway_secs)
    {
        return Err(AuthVerifyError::InvalidToken);
    }
    if !parsed.sub_non_empty {
        return Err(AuthVerifyError::MissingIdentity);
    }

    let mut identity = parsed.identity;
    match user_id_field {
        UserIdField::Username => {
            if !crate::jwks::is_valid_directory_query(&identity, crate::jwks::MAX_USERNAME_BYTES) {
                return Err(AuthVerifyError::MissingIdentity);
            }
        }
        UserIdField::Uuid => match crate::jwks::canonicalize_uuid(&identity) {
            Some(Cow::Borrowed(_)) => {}
            Some(Cow::Owned(canonical)) => identity = canonical,
            None => return Err(AuthVerifyError::MissingIdentity),
        },
    }

    Ok(VerifiedExchangedCaller {
        identity,
        repository_id: parsed.repository_id,
        actions: parsed.actions,
    })
}

impl CallerClaims {
    /// Builds an evaluated [`CallerClaims`] profile using the default [`PolicyConfig`].
    pub fn from_login_claims(
        raw: RawLoginClaims,
        static_projects: &BTreeMap<String, StaticProjectConfig>,
        user_id_field: UserIdField,
    ) -> Option<Self> {
        Self::from_login_claims_with_policy(
            raw,
            static_projects,
            user_id_field,
            &PolicyConfig::default(),
        )
    }

    /// Builds an evaluated [`CallerClaims`] profile from verified login claims, static project settings, and `policy`.
    pub fn from_login_claims_with_policy(
        raw: RawLoginClaims,
        static_projects: &BTreeMap<String, StaticProjectConfig>,
        user_id_field: UserIdField,
        policy: &PolicyConfig,
    ) -> Option<Self> {
        if raw.sub.is_empty() {
            return None;
        }
        let raw_identity = match raw.identity.or(raw.identity_namespaced) {
            Some(PresentStringClaim::Valid(s)) => s,
            Some(PresentStringClaim::Invalid) => return None,
            None => raw.sub.clone(),
        };
        let identity = match user_id_field {
            UserIdField::Username => {
                if !crate::jwks::is_valid_directory_query(
                    &raw_identity,
                    crate::jwks::MAX_USERNAME_BYTES,
                ) {
                    return None;
                }
                raw_identity
            }
            UserIdField::Uuid => match crate::jwks::canonicalize_uuid(&raw_identity) {
                Some(Cow::Borrowed(_)) => raw_identity,
                Some(Cow::Owned(canonical)) => canonical,
                None => return None,
            },
        };
        let username = match user_id_field {
            UserIdField::Username => identity.clone(),
            UserIdField::Uuid => raw
                .preferred_username
                .filter(|val| {
                    crate::jwks::is_valid_directory_query(val, crate::jwks::MAX_USERNAME_BYTES)
                })
                .unwrap_or_else(|| identity.clone()),
        };
        let display_name = raw
            .name
            .filter(|val| {
                crate::jwks::is_valid_directory_query(val, crate::jwks::MAX_DISPLAY_NAME_BYTES)
            })
            .unwrap_or_else(|| username.clone());

        let mut is_c_level = false;
        let mut is_employee = false;
        let mut is_partner = false;
        let mut can_create_any = false;
        let mut global_actions = ActionSet::EMPTY;
        let mut projects: BTreeMap<String, ProjectGrant> = BTreeMap::new();

        if let Some(rfs) = raw.rfs_lore {
            is_c_level |= rfs.is_c_level;
            is_employee |= rfs.is_employee;
            is_partner |= rfs.is_partner;
            can_create_any |= rfs.can_create_any;
            global_actions = global_actions.union(rfs.global_actions);
            for (raw_slug, raw_proj) in rfs.projects {
                let trimmed = raw_slug.trim();
                let slug = if trimmed.len() == raw_slug.len()
                    && !raw_slug.bytes().any(|b| b.is_ascii_uppercase())
                {
                    raw_slug
                } else {
                    trimmed.to_ascii_lowercase()
                };
                if !is_valid_project_slug(&slug) {
                    continue;
                }
                let static_vis = static_projects
                    .get(slug.as_str())
                    .map_or(ProjectVisibility::Internal, |cfg| cfg.visibility);
                let claim_vis = raw_proj.visibility.merge(static_vis);
                if raw_proj.actions.is_empty()
                    && !raw_proj.can_create_repo
                    && claim_vis == ProjectVisibility::Internal
                {
                    continue;
                }
                let entry = projects.entry(slug).or_default();
                entry.actions = entry.actions.union(raw_proj.actions);
                entry.can_create_repo |= raw_proj.can_create_repo;
                entry.visibility = entry.visibility.merge(claim_vis);
            }
        }

        if let Some(groups) = raw.groups {
            for group in &groups {
                if policy.admin_groups.iter().any(|adm| adm == group) {
                    is_c_level = true;
                    can_create_any = true;
                }
                if !policy.employee_group.is_empty() && group == &policy.employee_group {
                    is_employee = true;
                }
                if !policy.partner_group.is_empty() && group == &policy.partner_group {
                    is_partner = true;
                }
            }

            for (slug, cfg) in static_projects {
                if cfg.read_groups.is_empty()
                    && cfg.write_groups.is_empty()
                    && cfg.lead_groups.is_empty()
                {
                    continue;
                }
                let mut matched_actions = ActionSet::EMPTY;
                let mut matched_create = false;
                if cfg
                    .read_groups
                    .iter()
                    .any(|g| groups.iter().any(|cg| cg == g))
                {
                    matched_actions.insert(LoreAction::Read);
                }
                if cfg
                    .write_groups
                    .iter()
                    .any(|g| groups.iter().any(|cg| cg == g))
                {
                    matched_actions.insert(LoreAction::Read);
                    matched_actions.insert(LoreAction::Write);
                }
                if cfg
                    .lead_groups
                    .iter()
                    .any(|g| groups.iter().any(|cg| cg == g))
                {
                    matched_actions.insert(LoreAction::Read);
                    matched_actions.insert(LoreAction::Write);
                    matched_actions.insert(LoreAction::Admin);
                    matched_actions.insert(LoreAction::Presign);
                    matched_create = true;
                }
                if !matched_actions.is_empty() {
                    if let Some(entry) = projects.get_mut(slug.as_str()) {
                        entry.actions = entry.actions.union(matched_actions);
                        entry.can_create_repo |= matched_create;
                        entry.visibility = entry.visibility.merge(cfg.visibility);
                    } else {
                        projects.insert(
                            slug.clone(),
                            ProjectGrant {
                                actions: matched_actions,
                                can_create_repo: matched_create,
                                visibility: cfg.visibility,
                            },
                        );
                    }
                }
            }
        }

        if is_c_level {
            can_create_any = true;
            global_actions = ActionSet::ALL;
        }

        Some(Self {
            sub: raw.sub,
            identity,
            username,
            display_name,
            is_service_account: raw.is_service_account.unwrap_or(false),
            exp: raw.exp,
            token_iat: raw.iat,
            is_c_level,
            is_employee,
            is_partner,
            can_create_any,
            global_actions,
            projects,
        })
    }
}

/// Parses an optional `lore_visibility` string, failing closed to [`ProjectVisibility::Restricted`]
/// on any value other than `None` or case-insensitive `"internal"`.
pub(crate) fn parse_claim_visibility(raw: Option<&str>) -> ProjectVisibility {
    match raw {
        None => ProjectVisibility::Internal,
        Some(val) if val.trim().eq_ignore_ascii_case("internal") => ProjectVisibility::Internal,
        Some(_) => ProjectVisibility::Restricted,
    }
}

/// Validated `<project>/<repository>` name borrowing its project slug and full name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProjectRepoName<'a> {
    pub project: &'a str,
    pub full_name: &'a str,
}

/// Returns whether `slug` is a valid lowercase Rogue Fairy project identifier.
pub fn is_valid_project_slug(slug: &str) -> bool {
    let bytes = slug.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_PROJECT_SLUG_BYTES {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
}

fn is_valid_repo_segment(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    !bytes.is_empty()
        && bytes[0] != b'.'
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Parses and validates a project-scoped Lore repository name `<project>/<repository>`.
pub fn parse_project_repository_name(name: &str) -> Result<ProjectRepoName<'_>, PolicyError> {
    if name.is_empty() || name.len() > MAX_REPOSITORY_NAME_BYTES {
        return Err(PolicyError::InvalidRepositoryNameLength);
    }

    let Some((project, repo_path)) = name.split_once('/') else {
        return Err(PolicyError::MissingProjectNamespace);
    };

    if repo_path.is_empty() {
        return Err(PolicyError::MissingProjectNamespace);
    }

    if !is_valid_project_slug(project) {
        return Err(PolicyError::InvalidProjectSlug {
            project: project.to_owned(),
        });
    }

    for segment in repo_path.split('/') {
        if !is_valid_repo_segment(segment) {
            return Err(PolicyError::InvalidRepositorySegment {
                name: name.to_owned(),
            });
        }
    }

    Ok(ProjectRepoName {
        project,
        full_name: name,
    })
}

/// Returns whether `caller` may register a new repository in `project`.
pub fn may_create_repository(caller: &CallerClaims, project: &str) -> bool {
    caller.is_c_level
        || caller.can_create_any
        || caller
            .projects
            .get(project)
            .is_some_and(|grant| grant.can_create_repo)
}

/// Computes the effective visibility of `project`, keeping `Restricted` whenever any source sets it.
pub fn resolve_project_visibility(
    caller: &CallerClaims,
    project: &str,
    stored: Option<ProjectVisibility>,
    configured: Option<ProjectVisibility>,
) -> ProjectVisibility {
    let from_caller = caller
        .projects
        .get(project)
        .map_or(ProjectVisibility::Internal, |grant| grant.visibility);
    from_caller
        .merge(stored.unwrap_or(ProjectVisibility::Internal))
        .merge(configured.unwrap_or(ProjectVisibility::Internal))
}

/// Resolves static `[projects]` and live `authentik` group visibility for `project`,
/// treating unconfigured projects absent from a live `authentik` group map as `Restricted`.
pub fn resolve_configured_or_live_visibility(
    project: &str,
    static_projects: &BTreeMap<String, StaticProjectConfig>,
    authentik_projects: Option<&std::collections::HashMap<String, ProjectVisibility>>,
) -> ProjectVisibility {
    if let Some(cfg) = static_projects.get(project) {
        let live = authentik_projects
            .and_then(|projects| projects.get(project).copied())
            .unwrap_or(ProjectVisibility::Internal);
        return cfg.visibility.merge(live);
    }
    authentik_projects.map_or(ProjectVisibility::Internal, |projects| {
        projects
            .get(project)
            .copied()
            .unwrap_or(ProjectVisibility::Restricted)
    })
}

/// Returns whether `caller`'s effective permissions on any project can change with [`ProjectVisibility`].
pub const fn caller_depends_on_any_project_visibility(caller: &CallerClaims) -> bool {
    !caller.is_c_level
        && caller.is_employee
        && !caller.is_partner
        && !caller.global_actions.contains(LoreAction::Write)
}

/// Returns whether `caller`'s effective permissions on `project` depend on [`ProjectVisibility`].
pub fn caller_depends_on_project_visibility(caller: &CallerClaims, project: &str) -> bool {
    if !caller_depends_on_any_project_visibility(caller) {
        return false;
    }
    match caller.projects.get(project) {
        Some(grant) if grant.visibility == ProjectVisibility::Restricted => false,
        Some(grant) => !caller
            .global_actions
            .union(grant.actions)
            .contains(LoreAction::Write),
        None => !caller.global_actions.contains(LoreAction::Write),
    }
}

/// Computes all Lore actions `caller` holds on `project` under `visibility` as a stack bitmask.
///
/// Accounts carrying `Rogue Fairy Studios - Partners` never receive baseline
/// internal studio employee access unless they also carry `C-Level` or `authentik Admins`.
pub fn granted_action_set_on_project(
    caller: &CallerClaims,
    project: &str,
    visibility: ProjectVisibility,
) -> ActionSet {
    if caller.is_c_level {
        return ActionSet::ALL;
    }

    let project_grant = caller.projects.get(project);
    let effective_visibility = visibility
        .merge(project_grant.map_or(ProjectVisibility::Internal, |grant| grant.visibility));

    let mut actions = caller.global_actions;

    if effective_visibility == ProjectVisibility::Internal
        && caller.is_employee
        && !caller.is_partner
    {
        actions.insert(LoreAction::Read);
        actions.insert(LoreAction::Write);
    }

    if let Some(grant) = project_grant {
        actions = actions.union(grant.actions);
    }

    if !actions.is_empty() {
        actions.insert(LoreAction::Read);
    }

    actions
}

fn identities_match(lhs: &str, rhs: &str, user_id_field: UserIdField) -> bool {
    match user_id_field {
        UserIdField::Username => lhs == rhs,
        UserIdField::Uuid => match (
            crate::jwks::canonicalize_uuid(lhs),
            crate::jwks::canonicalize_uuid(rhs),
        ) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        },
    }
}

/// Returns whether `caller` holds permission to unregister `repo`.
///
/// Matches Lore Server's `may_administer_repository` rule: `Owner`, `Admin`,
/// or the repository's original `creator` holding `Write`.
pub fn may_unregister_repository(
    caller: &VerifiedCaller,
    repo: &RepositoryRecord,
    effective_visibility: ProjectVisibility,
    user_id_field: UserIdField,
) -> bool {
    match caller {
        VerifiedCaller::Login(claims) => {
            let actions =
                granted_action_set_on_project(claims, &repo.project, effective_visibility);
            actions.contains(LoreAction::Owner)
                || actions.contains(LoreAction::Admin)
                || (actions.contains(LoreAction::Write)
                    && identities_match(&claims.identity, &repo.creator, user_id_field))
        }
        VerifiedCaller::Exchanged(claims) => {
            claims.repository_id == repo.id
                && (claims.actions.contains(LoreAction::Owner)
                    || claims.actions.contains(LoreAction::Admin)
                    || (claims.actions.contains(LoreAction::Write)
                        && identities_match(&claims.identity, &repo.creator, user_id_field)))
        }
    }
}

/// Returns whether `caller` holds any Lore action on `repo`, for scoping directory queries.
pub fn may_access_partition(
    caller: &VerifiedCaller,
    repo: &RepositoryRecord,
    effective_visibility: ProjectVisibility,
) -> bool {
    match caller {
        VerifiedCaller::Login(claims) => {
            !granted_action_set_on_project(claims, &repo.project, effective_visibility).is_empty()
        }
        VerifiedCaller::Exchanged(claims) => {
            claims.repository_id == repo.id && !claims.actions.is_empty()
        }
    }
}

/// Parses a rendered `resource_id` back into its non-zero [`RepositoryId`] without allocating.
pub fn parse_resource_claim_id(resource_id: &str, template: &str) -> Option<RepositoryId> {
    let (prefix, suffix) = template.split_once("{id}")?;
    let hex_part = resource_id.strip_prefix(prefix)?.strip_suffix(suffix)?;
    if hex_part.len() != 32
        || !hex_part
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let ctx = Context::from_str(hex_part).ok()?;
    (!ctx.is_zero()).then(|| RepositoryId::from(ctx))
}

/// Renders `repository` through `resource_id_template` (for example `urc-<hex>`).
pub fn render_resource_id(resource_id_template: &str, repository: RepositoryId) -> String {
    if let Some((prefix, suffix)) = resource_id_template.split_once("{id}")
        && !suffix.contains("{id}")
    {
        let mut out = String::with_capacity(prefix.len() + 32 + suffix.len());
        out.push_str(prefix);
        let _ = write!(out, "{repository}");
        out.push_str(suffix);
        return out;
    }
    resource_id_template.replace("{id}", &repository.to_string())
}

# Rogue Fairy Studios — authentik and per-project Lore setup

Configuration, [authentik](https://goauthentik.io) (see the authentik documentation) blueprints, and the `rfs-lore-bridge` service that connect [Lore version control](../../../docs/glossary.md#lore) to Rogue Fairy Studios' identity provider (`https://auth.telluriancorp.info`) and enforce per-project repository creation and access (`<project>/<repository>`).

Lore Server and Lore CLI run unmodified upstream binaries in Tier 2 (`ResourceGrantsAuthorizer` plus `user_service` catalog).

## Architecture

| Component | Production endpoint | Local endpoint | Role |
| --- | --- | --- | --- |
| **Tellurian authentik** | `https://auth.telluriancorp.info` | `http://localhost:9000` | Signs interactive device-code tokens (`rfs-lore-cli`) and headless CI tokens (`rfs-lore-ci`), embedding base studio memberships and per-project group attributes in the `rfs_lore` claim when the `lore` scope is requested. |
| `rfs-lore-bridge` | `https://lore-auth.roguefairy.net` | `http://localhost:8190` | Rust HTTP and gRPC service (`bridge/`). Enforces `<project>/<repository>` naming and project creation rules on `RepositoryRegister`, filters `RepositoryList` by project grants, mints short-lived `ES256` `at+jwt` partition tokens on `/token` (RFC 8693), and serves `UserService` (`UserGet`, `UserFind`). |
| **Lore Server** | `lores://lore.roguefairy.net` | `lore://localhost:41337` | `loreserver` binary. Verifies authentik login tokens (`JWT`) for `RepositoryCreate` and `RepositoryList`, and verifies Bridge-signed partition tokens (`at+jwt`) on `resources` (`urc-{id}`) for every repository operation. |

## Studio groups and access policy

The `Rogue Fairy Lore Scope` mapping (`scope_name: lore`) evaluates existing Tellurian authentik groups alongside project groups created under `Rogue Fairy Studios - Lore Projects`:

| authentik group | Default Lore access | Repository creation (`<project>/<repository>`) |
| --- | --- | --- |
| `Rogue Fairy Studios - C-Level` | Same access for `authentik Admins`: all 8 actions (`read`, `write`, `owner`, `admin`, `migrate`, `push-protected`, `obliterate`, `presign`) on every internal and restricted project | Any `<project>/<repository>` whose project exists in authentik groups or `[projects]` |
| `Rogue Fairy Studios` | Studio employees: `read` and `write` on every `internal` project; no access to `restricted` projects without an explicit project group | Denied unless a project group sets `lore_can_create_repo: true` |
| `Rogue Fairy Studios - Partners` | External partners: zero global access; `RepositoryList` and `/token` return only projects explicitly granted by a project group | Denied unless a project group sets `lore_can_create_repo: true` |
| `Rogue Fairy Studios - Lore CI` | Headless `ak-rfs-lore-ci-client_credentials` account: `read`, `write`, and `push-protected` across all projects, including `restricted` ones (`lore_project: "*"`; replace with per-project CI groups if a confidential project requires separate CI credentials) | Denied (`lore_can_create_repo: false`) |

> [!IMPORTANT]
> Partner isolation fails closed. If an account belongs to both `Rogue Fairy Studios` and `Rogue Fairy Studios - Partners` (without `C-Level` or `authentik Admins`), `rfs-lore-bridge` treats the caller as a partner and grants no automatic `internal` studio access.

## Native authentik group attribute format

Each project group in authentik is an `authentik_core.group` (recommended parent: `Rogue Fairy Studios - Lore Projects`) carrying custom JSON `attributes`:

```yaml
lore_project: ghostlore          # Lowercase slug `[a-z0-9][a-z0-9._-]{0,63}`, or "*" for studio-wide grants
lore_visibility: internal        # "internal" (default; studio employees get read+write) or "restricted"
lore_actions:                    # Subset of: read, write, owner, admin, migrate, push-protected, obliterate, presign
  - read
  - write
  - admin
  - obliterate
  - presign
lore_can_create_repo: true       # Boolean: whether members can create `<project>/<repository>` repositories (deletion requires `owner`, `admin`, or the creator holding `write`)
```

### Add a new project in authentik

To onboard a new game or tool project (for example, `projectx`) in the authentik admin interface (**Directory > Groups**):

1. Create the project leads group `Rogue Fairy Studios - ProjectX - Leads` with parent `Rogue Fairy Studios - Lore Projects` and set its custom attributes:

   ```yaml
   lore_project: projectx
   lore_visibility: internal
   lore_actions:
     - read
     - write
     - admin
     - presign
   lore_can_create_repo: true
   ```

   Assign the project's technical lead or producer to this group. For an unannounced or confidential project that regular `Rogue Fairy Studios` employees must not see automatically, set `lore_visibility: restricted` and add a second team group (`lore_actions: [read, write]`, `lore_can_create_repo: false`) for assigned developers.

2. Create an external partner group when external partners collaborate on `projectx`, keeping them in `Rogue Fairy Studios - Partners`. Set `lore_project: projectx` and `lore_can_create_repo: false`, with `lore_actions: [read]` for read-only partners or `lore_actions: [read, write]` for co-development partners.

3. Create repositories under the `projectx/` namespace as a project lead or C-Level member:

   ```bash
   lore auth login lores://lore.roguefairy.net
   lore repository create lores://lore.roguefairy.net/projectx/game
   lore repository create lores://lore.roguefairy.net/projectx/art-source
   ```

   When a project lead creates a project's first repository, `rfs-lore-bridge` merges the lead's token visibility with authentik's Core API (`/api/v3/core/groups/`) so a secondary group that omits `lore_visibility` never downgrades a `restricted` project.

   When a C-Level member outside the project group creates a project's first repository, `rfs-lore-bridge` resolves `lore_visibility` from `/api/v3/core/groups/` or `[projects.<slug>]`, refusing unknown project slugs. Any unrecognized `lore_visibility` string fails closed to `restricted`, and standalone names without a `<project>/` prefix (such as `lores://lore.roguefairy.net/game`) fail validation on `RepositoryRegister`.

## Production deployment

### 1. Import the authentik blueprint

1. Upload [`blueprint.yaml`](blueprint.yaml) to Tellurian authentik (**Customization > Blueprints**), or mount it into the authentik worker container, and apply `Rogue Fairy Studios - Lore OIDC`.
2. Open **System > Brands**, edit the active brand for `auth.telluriancorp.info`, and set **Device code flow** to `rfs-lore-device-code` (`Rogue Fairy Lore Device Code`) if the brand has no device flow configured. Without a device code flow on the brand, authentik answers device login URLs with HTTP 404.
3. Open **Applications > Providers > rfs-lore-ci** and copy the generated **Client Secret** for CI pipelines (`LORE_CLIENT_SECRET`).
4. Open **Applications > Providers** and verify that both `rfs-lore-cli` and `rfs-lore-ci` resolved a non-null **Signing Key** (sharing the same certificate so Lore Server verifies both issuers against discovery) and that `rfs-lore-cli` resolved `rogue-fairy-authentication` as its **Authentication flow** (`!Find` expressions evaluate to `null` if a certificate or flow name differs on the target instance).

### 2. Deploy `rfs-lore-bridge` on Railway

Build `rfs-lore-bridge` from the repository root using [`bridge/Dockerfile`](bridge/Dockerfile), attach a persistent volume at `/data`, and generate a persistent `ES256` PKCS#8 signing key:

```bash
cargo run --manifest-path contrib/oidc/roguefairy/bridge/Cargo.toml --release -- --generate-signing-key
```

Configure the service with [`bridge.example.toml`](bridge.example.toml) or `RFS_LORE_*` environment variables:

| Environment variable | Production value |
| --- | --- |
| `RFS_LORE_ISSUER` | `https://lore-auth.roguefairy.net` |
| `RFS_LORE_LOGIN_ISSUERS` | `https://auth.telluriancorp.info/application/o/rfs-lore-cli/,https://auth.telluriancorp.info/application/o/rfs-lore-ci/` |
| `RFS_LORE_LOGIN_AUDIENCES` | `https://lore.roguefairy.net` |
| `RFS_LORE_AUDIENCE` | `https://lore.roguefairy.net` |
| `RFS_LORE_ROOT_DOMAINS` | `.roguefairy.net` |
| `RFS_LORE_RESOURCE_PREFIX` | `https://lore.roguefairy.net/partitions/` |
| `RFS_LORE_STATE_PATH` | `/data/registry-state.json` |
| `RFS_LORE_USER_STATE_PATH` | `/data/users-state.json` (optional; separates user directory snapshots from `RFS_LORE_STATE_PATH`) |
| `RFS_LORE_SIGNING_KEY_B64` | Base64 PKCS#8 P-256 key printed by `--generate-signing-key` |
| `RFS_LORE_AUTHENTIK_URL` | `https://auth.telluriancorp.info` (authentik Core API for `UserService` fallback and C-Level project visibility lookups) |
| `RFS_LORE_AUTHENTIK_API_TOKEN` | Read-only authentik Core API token for `/api/v3/core/users/` and `/api/v3/core/groups/` |
| `RFS_LORE_AUTHENTIK_USER_ID_FIELD` | `username` (default; matches `Rogue Fairy Lore Scope`) or `uuid` (requires `Rogue Fairy Lore Scope` to emit `"identity": str(request.user.uuid)` so login tokens carry a 36-character UUID) |

`rfs-lore-bridge` checks `RFS_LORE_BIND` first, then `bind` in TOML, then `0.0.0.0:$PORT` on Railway, and defaults to `0.0.0.0:8190`. When `RFS_LORE_GRPC_BIND` is unset, `RFS_LORE_BIND` multiplexes HTTP/1.1 OIDC endpoints and HTTP/2 (`h2c`) gRPC services on the same port.

When `RFS_LORE_GRPC_BIND` is set (for example, `[::]:8191` behind a split ingress), the public `RFS_LORE_BIND` listener serves `/.well-known/openid-configuration`, `/jwks`, `/token`, `/health_check`, and `/lore.user.v1.UserService/*` while omitting `/lore.user.v1.RepositoryRegistryService/*`, and `RFS_LORE_GRPC_BIND` serves both gRPC services. Expose `/health_check` as the readiness probe.

### 3. Deploy `loreserver`

Build `loreserver` from the repository root using [`Dockerfile.loreserver`](Dockerfile.loreserver) (which layers [`roguefairy.toml`](roguefairy.toml) over `default.toml` with `/data` local stores and drops privileges after fixing volume ownership), or merge [`roguefairy.toml`](roguefairy.toml) into an existing Lore Server deployment:

- `[environment.endpoint] user_url = "https://lore-auth.roguefairy.net"` routes `RepositoryList`, `RepositoryRegister`, `RepositoryUnregister`, `UserGet`, and `UserFind` to `rfs-lore-bridge`.
- `[server.auth] jwt_typ = ["JWT", "at+jwt"]` accepts authentik login tokens on `RepositoryCreate` and `RepositoryList`, and Bridge-minted `at+jwt` access tokens on partition-scoped requests.
- `[server.auth] resource_claim = "resources"` and `[server.auth.oidc] token_exchange_issuer = "https://lore-auth.roguefairy.net"` activate Tier 2 per-partition authorization.
- Attach a persistent volume at `/data` and probe `/health_check` on HTTP port `41339`. Optionally set `LORE__SERVER__HTTP__PRESIGNED_URL_HMAC_KEY` to a 64-character hex secret for pre-signed URLs, or `RFS_LORE_LOCAL_TOML` for runtime TOML overrides.
- Over HTTPS and HTTP/2 proxies that don't forward raw UDP `41337` (such as Railway public HTTP/2 domains), clients connect with `grpcs://lore.roguefairy.net/<project>/<repository>`; when UDP `41337` is reachable directly, clients connect with `lores://lore.roguefairy.net/<project>/<repository>`.
- On the public ingress for `https://lore-auth.roguefairy.net`, expose `/.well-known/openid-configuration`, `/jwks`, `/token`, `/health_check`, and `/lore.user.v1.UserService/*` to Lore CLI clients.
- Block `/lore.user.v1.RepositoryRegistryService/*` from public internet traffic — either with an edge rule or by routing internal registry traffic to `RFS_LORE_GRPC_BIND` — so external clients can't call `RepositoryRegister` or `RepositoryUnregister` directly without going through `loreserver`.

## Local walkthrough with Docker Compose

[`compose.yaml`](compose.yaml) starts PostgreSQL, authentik 2026.8.5 with [`blueprint-local.yaml`](blueprint-local.yaml), and `rfs-lore-bridge` with [`bridge-local.toml`](bridge-local.toml).

> [!WARNING]
> `blueprint-local.yaml` and `compose.yaml` use fixed passwords and plain HTTP on `127.0.0.1` for local verification only. Never import `blueprint-local.yaml` into a production authentik instance.

### Test personas in `blueprint-local.yaml`

| Username | Password | Groups | Effective permissions |
| --- | --- | --- | --- |
| `alice` | `alice` | `Rogue Fairy Studios - C-Level` | Full actions and repository creation across every project |
| `carla` | `carla` | `Rogue Fairy Studios`, `GhostLore - Leads`, `SecretProto - Leads` | Creates and administers `ghostlore/*` (`internal`) and `secretproto/*` (`restricted`); `read` and `write` on other `internal` projects |
| `bruno` | `bruno` | `Rogue Fairy Studios` | `read` and `write` on `internal` projects (`ghostlore/*`, `animafaber/*`); can't create repositories; denied on `secretproto/*` |
| `diego` | `diego` | `Rogue Fairy Studios - Partners`, `GhostLore - Partners` | `read` only on `ghostlore/*`; denied on `animafaber/*` and `secretproto/*` |
| `eva` | `eva` | `Rogue Fairy Studios - Partners` | Zero access across all projects |
| `ak-rfs-lore-ci-client_credentials` | client secret `rfs-lore-ci-dev-secret` | `Rogue Fairy Studios - Lore CI` | `read`, `write`, and `push-protected` on all registered repositories |

### Local stack walkthrough

1. Start authentik and `rfs-lore-bridge`, wait until authentik's discovery document responds at `http://localhost:9000/application/o/rfs-lore-cli/.well-known/openid-configuration`, and start `loreserver`:

   ```bash
   cd contrib/oidc/roguefairy
   docker compose up -d --build
   loreserver --config . --env roguefairy-local
   ```

2. Sign in as `carla` (GhostLore and SecretProto lead), create an `internal` repository and a `restricted` repository, push an initial revision, and protect `main`:

   ```bash
   export LORE_AUTH_PATH=/tmp/lore-rfs-demo/carla
   lore auth login lore://localhost:41337

   mkdir -p /tmp/lore-rfs-demo/carla-ghostlore && cd /tmp/lore-rfs-demo/carla-ghostlore
   lore repository create lore://localhost:41337/ghostlore/client
   echo "v1" > README.md
   lore stage README.md
   lore commit "Initial GhostLore revision"
   lore push
   lore branch protect main

   mkdir -p /tmp/lore-rfs-demo/carla-secret && cd /tmp/lore-rfs-demo/carla-secret
   lore repository create lore://localhost:41337/secretproto/prototype
   ```

3. Sign in as `bruno` (studio employee). `bruno` can clone `ghostlore/client` and push to a feature branch, can't create repositories, can't push to protected `main`, and can't clone `secretproto/prototype`:

   ```bash
   export LORE_AUTH_PATH=/tmp/lore-rfs-demo/bruno
   lore auth login lore://localhost:41337
   lore repository list lore://localhost:41337

   lore clone lore://localhost:41337/ghostlore/client /tmp/lore-rfs-demo/bruno-ghostlore
   cd /tmp/lore-rfs-demo/bruno-ghostlore
   lore branch create feature/combat
   echo "combat" > combat.txt
   lore stage combat.txt
   lore commit "Add combat tuning"
   lore push
   ```

4. Sign in as `diego` (external partner assigned to `GhostLore - Partners`). `diego` sees only `ghostlore/client` in `lore repository list`, can clone it, and is refused when pushing:

   ```bash
   export LORE_AUTH_PATH=/tmp/lore-rfs-demo/diego
   lore auth login lore://localhost:41337
   lore repository list lore://localhost:41337
   lore clone lore://localhost:41337/ghostlore/client /tmp/lore-rfs-demo/diego-ghostlore
   ```

5. Sign in headlessly as CI (`lore-ci-rfs`) and push to the protected `main` branch:

   ```bash
   export LORE_AUTH_PATH=/tmp/lore-rfs-demo/ci
   LORE_CLIENT_SECRET=rfs-lore-ci-dev-secret lore auth login lore://localhost:41337 --client-id lore-ci-rfs
   lore clone lore://localhost:41337/ghostlore/client /tmp/lore-rfs-demo/ci-ghostlore
   cd /tmp/lore-rfs-demo/ci-ghostlore
   echo "build=101" > build.txt
   lore stage build.txt
   lore commit "Stamp CI build 101"
   lore push
   ```

6. Stop the local environment when finished:

   ```bash
   docker compose down -v
   rm -rf /tmp/lore-rfs-demo
   ```

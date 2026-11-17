# Keston ID

The OpenID Connect identity provider for every Keston app, at
**https://id.keston.co**. People sign in once with their Keston account;
apps (Keston Learn, Keston Forms, Keston Work, partners) get standard
OIDC tokens.

- **Backend:** Go, [zitadel/oidc](https://github.com/zitadel/oidc) (OpenID
  Certified) for the protocol, Postgres for everything else.
- **Frontend:** Vue 3 + [Keston UI](https://ui.keston.co), built from Keston
  UI's "Examples/Keston ID" and "Examples/App pages" stories, embedded in the
  Go binary.
- **Runs as:** one small, stateless container. All state (sessions, signing
  keys, tokens) is in Postgres, so you can run as many replicas as you like
  behind a load balancer with no sticky sessions. Live, it runs as the Azure
  Container App `keston-id` behind Cloudflare (see
  [Live on Azure](#live-on-azure)).

## What it does

| | |
|---|---|
| OIDC / OAuth 2.0 | Authorization code flow with PKCE, refresh tokens (rotated on every use), JWT access tokens (RS256), userinfo, introspection, revocation, RP-initiated logout, discovery |
| Sign-in | Email and password (Argon2id), failed attempts lock the account for 15 minutes after 5 tries |
| Multi-factor authentication (MFA) | Authenticator app (TOTP), 10 one-time backup codes; admins can turn it off for someone who has lost theirs |
| Consent | Required and optional scopes; remembered per app; Keston's own apps can skip it |
| Account pages | Profile, where you're signed in (sign out other devices), password, MFA, connected apps (remove access) |
| Operations | Migrations and signing-key creation guarded by Postgres advisory locks, signing-key rotation every 90 days, hourly cleanup, `/healthz` and `/readyz`, JSON logs, graceful shutdown |

Not yet: passkeys (WebAuthn), password reset by email, back-channel logout
to apps, an admin UI for users and apps (use the CLI below for now).

## Layout

```
cmd/keston-id/       main: serve, migrate, clients sync, orgs/users commands, healthcheck
internal/config/     settings from environment variables
internal/db/         Postgres pool, migrations (db/migrations/*.sql)
internal/store/      every SQL query
internal/oidcstore/  zitadel/oidc's op.Storage on top of the store
internal/api/        JSON API for the web UI (/api/…)
internal/server/     routes: OIDC endpoints, /api, the web UI, health checks
internal/secret/     AES-GCM for secrets at rest, Argon2id, random tokens
web/                 Vue + Keston UI; web/dist is embedded by web/embed.go
deploy/              apps to register (clients.local.json, clients.json), Caddyfile (local/legacy VPS only)
```

## Endpoints

| Path | |
|---|---|
| `/.well-known/openid-configuration` | Discovery |
| `/authorize` | Starts sign-in; sends people to `/sign-in?authRequestID=…` |
| `/oauth/token`, `/userinfo`, `/keys`, `/revoke`, `/oauth/introspect`, `/end_session` | Standard OIDC |
| `/sign-in`, `/mfa`, `/consent` | The sign-in pages |
| `/account` | Account pages |
| `/healthz`, `/readyz` | Liveness, and readiness (database reachable) |

## Addresses

| | Local | Live |
|---|---|---|
| Keston ID | http://id.keston.localhost | https://id.keston.co |
| Keston Work | http://work.keston.localhost | https://work.keston.co |

Browsers send every `*.localhost` name to your own machine, so the local
addresses need no hosts-file changes. Locally, Caddy (in `compose.yaml`) routes each
name to the right container. Until the Keston Work app exists,
`work.keston.localhost` is a stand-in page that shows what Keston ID sent
back (see `deploy/Caddyfile`).

## Run it locally (Docker)

```bash
docker compose up --build
```

No `.env` is needed: the defaults are the local ones. `setup` runs once to
apply migrations and register the local apps (`deploy/clients.local.json`),
then Keston ID and Caddy start. Create an account:

```bash
docker compose run --rm -it keston-id users create -email you@keston.school -name "Your Name" -organisation "The Keston School"
```

Then sign in to Keston Work through Keston ID:
[http://id.keston.localhost/authorize?client_id=work&…](http://id.keston.localhost/authorize?client_id=work&redirect_uri=http%3A%2F%2Fwork.keston.localhost%2Fcallback&response_type=code&scope=openid%20profile%20email%20staff%3Aread%20offline_access&state=test&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGkSz9IcjM&code_challenge_method=S256),
or go to http://id.keston.localhost/account.

The local Keston Work client secret is `keston-work-local-secret` (set
`KESTON_WORK_LOCAL_CLIENT_SECRET` to change it).

### Locked out, or lost your password

Five wrong passwords lock an account for 15 minutes. If someone can't wait, or
needs a new password and no admin can reset it in Keston Admin:

```bash
docker compose run --rm keston-id users unlock -email you@keston.school
```

```bash
docker compose run --rm -it keston-id users reset-password -email you@keston.school
```

`reset-password` reads the new password from `KESTON_ID_PASSWORD` or asks for it,
checks it against the organisation's password rules, unlocks the account and
signs it out everywhere, as an admin's reset in Keston Admin does. Live, run
the same commands inside the Azure container (see
[Command-line administration](#command-line-administration)); never paste
passwords into chat or scripts.

### Local test account

For local testing only (never create it on the live server):

```bash
docker compose run --rm -e KESTON_ID_PASSWORD="correct horse battery" keston-id users create -email john.doe@example.com -name "John Doe" -organisation "Example Ltd"
```

It signs in with that email and password, and has MFA
off. If MFA gets turned on and you lose the code, an admin can turn it off in
Keston Admin, or start again with
`docker compose down -v` (this deletes the local database).

Run several replicas behind Caddy locally:

```bash
docker compose up -d --scale keston-id=3
```

## Run it without Docker

Needs Go 1.27+, pnpm and Postgres. Keston ID is then at
http://id.keston.localhost:8080.

```bash
pnpm -C web install && pnpm -C web build
```

```bash
export KESTON_ID_DATABASE_URL="postgres://localhost:5432/keston_id?sslmode=disable"
```

```bash
go run ./cmd/keston-id clients sync deploy/clients.local.json
```

```bash
go run ./cmd/keston-id
```

To work on the UI with hot reload, run `pnpm -C web dev` too, and start the
server with `KESTON_ID_DEV_WEB_URL=http://localhost:5180`: the Go server then
passes UI requests to Vite.

With an `http://` issuer, Keston ID runs in development mode: cookies aren't
`Secure` and a built-in secret key is used. An `https://` issuer refuses to
start without a real `KESTON_ID_SECRET_KEY`.

## Live on Azure

Live is **https://id.keston.co**: the Container App `keston-id` in the
`rg-keston-prod` resource group (UK South), fronted by Cloudflare's proxy,
with Postgres 17 Flexible Server (private), secrets in Key Vault and images in
the `kestonprodacr` registry. It is defined in the **infra** repo
(`platform.bicep`, `apps.bicep`), whose README is the runbook from a fresh
Azure account to a working site, including DNS, Cloudflare rules, first admin
account, routine updates and troubleshooting. `compose.yaml`, `deploy/Caddyfile`
and `.env.live.example` here are for local development and the legacy VPS, not
for live.

Routine update of live (code only), from this repo:

```bash
az acr build -r kestonprodacr -t "id:$(git rev-parse --short HEAD)" -t id:latest .
az containerapp update -g rg-keston-prod -n keston-id --image kestonprodacr.azurecr.io/id:$(git rev-parse --short HEAD)
```

If `deploy/clients.json` or the migrations changed, run the
`keston-id-clients-sync` job first (infra README, "Routine updates"). Keep
`KESTON_ID_SECRET_KEY` (Key Vault secret `keston-id-secret-key`) safe and never
regenerate it: it decrypts signing keys and MFA secrets.

### Command-line administration

The binary has a few administrative commands. Locally use
`docker compose run --rm [-it] keston-id <command>`; live, run them in the
container:

```bash
az containerapp exec -g rg-keston-prod -n keston-id --command "/keston-id users role -email you@thekestongroup.com -role global_admin"
```

`exec` splits the command on spaces, so values can't contain spaces (set full
names later at https://id.keston.co/account). With Homebrew's az CLI, prefix
`WEBSOCKET_CLIENT_CA_BUNDLE=<path to az's certifi cacert.pem>` if you get
`CERTIFICATE_VERIFY_FAILED` (see the infra README, Troubleshooting).

| Command | |
|---|---|
| `keston-id migrate` | Apply database migrations and exit |
| `keston-id clients sync FILE` | Register / update apps from a JSON file |
| `keston-id orgs create -name … -domain … -admin-username … -admin-name … [-platform-admin]` | Create an organisation and its first global admin. Not for The Keston Group: that platform organisation is created automatically on every start (`KESTON_ID_PLATFORM_NAME`, `KESTON_ID_PLATFORM_DOMAIN`) |
| `keston-id users create -email … -name … [-role global_admin] [-platform-admin]` | Create an account in an existing organisation (by email domain). Prompts for a password, or reads `KESTON_ID_PASSWORD` |
| `keston-id users platform-admin -email … [-off]` | Make an account a platform admin (or remove it) |
| `keston-id users role -email … -role member\|global_admin` | Change an account's role. Keston Admin needs `global_admin` to show Users, Groups, Apps and Settings |
| `keston-id users unlock -email …` | Unlock an account locked by failed sign-ins |
| `keston-id users reset-password -email …` | Set a new password (also unlocks, and signs the person out everywhere) |

### Legacy: single VPS

The previous live setup ran this repo's `compose.yaml` with Caddy on a VPS.
It still works for a small self-hosted install, but it is not how Keston runs
now: point DNS at the VPS and open ports 80 and 443, copy `.env.live.example`
to `.env` and fill it in, then `docker compose up -d --build --scale keston-id=2`
and back up the `postgres` volume.

## Registering an app

Add it to `deploy/clients.json` and run `keston-id clients sync`. Confidential
apps (with a server) name an environment variable holding their secret in
`secretEnv`; leave it out for public apps (single-page or mobile), which must
use PKCE. `verification` is `owned` (The Keston Group's own), `verified`
(a checked partner) or `none` (shows a warning on the consent page).

### Keston-wide apps: file or Keston Admin

Keston-wide apps (every organisation has them) come from one of two places,
recorded per app in `clients.managed_by`:

- **`deployment`**: registered from `deploy/clients.json` by
  `keston-id clients sync`, which runs on every deploy and creates or updates
  them (name, redirect URIs, scopes, secret from `secretEnv`…). Keston Admin
  shows them as "Managed by deployment", read-only. Keston's own products
  (Learn, Forms, Work, Keston Admin itself) stay here: they need
  `verification: owned`, licences and secrets from Key Vault. To remove one,
  take it out of the file and delete or retire the row by hand.
- **`admin`**: created in Keston Admin by TKG Admins in The Keston Group
  (Apps → Add a Keston-wide app). Name, description, type (web with a
  generated secret, shown once and kept hashed, or single-page/mobile with
  PKCE), redirect URIs, scopes and links are edited there; a TKG Admin can
  retire one (it disappears for everyone and can't be signed in to) and bring
  it back. They never get Keston's own claims or audiences (`verification` is
  `none`), have no licences and show the consent prompt. Changes are audited.

`clients sync` only creates or updates apps that are new or `deployment`
managed; if the file names an ID that a TKG Admin owns, it logs a warning and
skips it, so the two never overwrite each other. Existing apps are all
`deployment` managed after the migration.

### App access

Per organisation and app: a default (Forced, Enabled, Disabled; Keston's own
products are Forced unless set) and ordered rules (`app_rules`). Rules match
users, groups and IP addresses (empty matches anyone); the first turned-on
match decides, otherwise the default applies. The decision is made in
`store.EffectiveAppsFrom` and enforced when signing in (`/authorize` and SAML
single sign-on, including the address the person signs in from), in
Connected apps and in an admin's view of someone's apps. Licences still
apply on top. Rules on IP addresses don't match where the address isn't known
(an admin looking at someone's apps).

### An organisation's own apps

Organisations add their own SSO apps in Keston Admin (Apps → Add an app),
with OpenID Connect (a web app with a secret, or a single-page or mobile app
with PKCE) or SAML 2.0 (from the app's metadata URL or XML, or its entity ID
and ACS URL). Only that organisation's users can sign in to them, there's no
consent prompt, and their tokens never carry Keston's own claims (`org`,
`perms`) or audiences.

SAML apps each get their own IdP endpoints (`internal/samlidp`):
`/saml/{app}/metadata` (also the IdP entity ID), `/saml/{app}/sso` and
`/saml/{app}/start` (IdP-initiated). NameID is the email address; the
attributes are `email`, `name`, `given_name`, `family_name` and `groups`.
Assertions are signed with one SAML certificate, made at start and kept
encrypted like the OIDC keys.

End-to-end tests (`go test -tags e2e ./internal/server/`) need a throwaway
Postgres; see the top of `internal/server/sso_apps_e2e_test.go`.

## Licence

Source-available under the [PolyForm Noncommercial License 1.0.0](LICENSE): free to use, modify and share for any noncommercial purpose. Required notice: Copyright The Keston Group (https://github.com/thekestongroup).

Please report security issues privately; see [SECURITY.md](SECURITY.md).

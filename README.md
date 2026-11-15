# Keston ID

The OpenID Connect identity provider for every Keston app, at
**https://id.keston.co**. People sign in once with their Keston account;
apps (Keston Learn, Keston Schools, Keston Work, partners) get standard
OIDC tokens.

- **Backend:** Go, [zitadel/oidc](https://github.com/zitadel/oidc) (OpenID
  Certified) for the protocol, Postgres for everything else.
- **Frontend:** Vue 3 + [Keston UI](https://ui.keston.co), built from Keston
  UI's "Examples/Keston ID" and "Examples/App pages" stories, embedded in the
  Go binary.
- **Runs as:** one small, stateless container. All state (sessions, signing
  keys, tokens) is in Postgres, so you can run as many replicas as you like
  behind a load balancer with no sticky sessions, and move to Kubernetes
  later without changes.

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
cmd/keston-id/       main: serve, migrate, clients sync, users create, healthcheck
internal/config/     settings from environment variables
internal/db/         Postgres pool, migrations (db/migrations/*.sql)
internal/store/      every SQL query
internal/oidcstore/  zitadel/oidc's op.Storage on top of the store
internal/api/        JSON API for the web UI (/api/…)
internal/server/     routes: OIDC endpoints, /api, the web UI, health checks
internal/secret/     AES-GCM for secrets at rest, Argon2id, random tokens
web/                 Vue + Keston UI; web/dist is embedded by web/embed.go
deploy/              apps to register (clients.local.json, clients.json), Caddyfile
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
addresses need no hosts-file changes. Caddy (in `compose.yaml`) routes each
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

### Local test account

For local testing only (never create it on the live server):

```bash
docker compose run --rm -e KESTON_ID_PASSWORD="correct horse battery" keston-id users create -email ben.smith@keston.school -name "Ben Smith" -organisation "The Keston School"
```

It signs in with that email and password, and has MFA
off. If MFA gets turned on and you lose the code, an admin can turn it off in
Keston Admin, or start again with
`docker compose down -v` (this deletes the local database).

Run several replicas behind Caddy, as on the VPS:

```bash
docker compose up -d --scale keston-id=3
```

## Run it without Docker

Needs Go 1.27+, pnpm and Postgres. Keston ID is then at
http://id.keston.localhost:4444.

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

## Live on the VPS

1. Point DNS for `id.keston.co` and `work.keston.co` at the VPS, and open
   ports 80 and 443.
2. Next to `compose.yaml`, copy `.env.live.example` to `.env` and fill it in:
   the secret key, a Postgres password and each app's client secret. Keep
   the secret key safe and backed up: it decrypts signing keys and MFA
   secrets.
3. Start it:

   ```bash
   docker compose up -d --build --scale keston-id=2
   ```

   Caddy gets HTTPS certificates for both names automatically, and spreads
   requests across the replicas.
4. Back up the `postgres` volume.

For Kubernetes later: the same image (`ghcr.io/thekestongroup/id`),
`keston-id clients sync …` as a Job, `serve` as a Deployment, `/healthz` and
`/readyz` as liveness and readiness probes, and an Ingress in place of Caddy.

## Registering an app

Add it to `deploy/clients.json` and run `keston-id clients sync`. Confidential
apps (with a server) name an environment variable holding their secret in
`secretEnv`; leave it out for public apps (single-page or mobile), which must
use PKCE. `verification` is `owned` (The Keston Group's own), `verified`
(a checked partner) or `none` (shows a warning on the consent page).

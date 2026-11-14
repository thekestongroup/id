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
| Two-step verification | Authenticator app (TOTP), 10 one-time backup codes |
| Consent | Required and optional scopes; remembered per app; Keston's own apps can skip it |
| Account pages | Profile, where you're signed in (sign out other devices), password, two-step, connected apps (remove access) |
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
deploy/              apps (OAuth clients) to register
```

## Endpoints

| Path | |
|---|---|
| `/.well-known/openid-configuration` | Discovery |
| `/authorize` | Starts sign-in; sends people to `/sign-in?authRequestID=…` |
| `/oauth/token`, `/userinfo`, `/keys`, `/revoke`, `/oauth/introspect`, `/end_session` | Standard OIDC |
| `/sign-in`, `/two-step`, `/consent` | The sign-in pages |
| `/account` | Account pages |
| `/healthz`, `/readyz` | Liveness, and readiness (database reachable) |

## Run it locally

Needs Go 1.27+, pnpm and Postgres.

```bash
createdb keston_id
```

```bash
pnpm -C web install && pnpm -C web build
```

```bash
export KESTON_ID_DATABASE_URL="postgres://localhost:5432/keston_id?sslmode=disable"
```

```bash
go run ./cmd/keston-id clients sync deploy/clients.dev.json
```

```bash
go run ./cmd/keston-id users create -email you@keston.school -name "Your Name" -organisation "The Keston School"
```

```bash
go run ./cmd/keston-id
```

Then open
`http://localhost:4444/authorize?client_id=demo&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&response_type=code&scope=openid%20profile%20email%20offline_access&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGkSz9IcjM&code_challenge_method=S256&state=test`,
or `http://localhost:4444/account`.

To work on the UI with hot reload, run `pnpm -C web dev` too, and start the
server with `KESTON_ID_DEV_WEB_URL=http://localhost:5180`: the Go server then
passes UI requests to Vite.

With an `http://` issuer, Keston ID runs in development mode: cookies aren't
`Secure` and a built-in secret key is used. Never use that in production.

## Run it with Docker

```bash
cp .env.example .env
```

Fill in `.env` (at least `KESTON_ID_SECRET_KEY` and the client secrets), then:

```bash
docker compose up --build
```

`setup` runs once: it applies migrations and registers the apps in
`deploy/clients.json` (set `KESTON_ID_CLIENTS_FILE=clients.dev.json` in `.env`
for the local demo app instead). Then `keston-id` starts on
http://localhost:4444. Create an account with:

```bash
docker compose run --rm -it keston-id users create -email you@keston.school -name "Your Name"
```

## On the VPS

1. Set `KESTON_ID_ISSUER=https://id.keston.co` and a real
   `KESTON_ID_SECRET_KEY` (`openssl rand -base64 32`) in `.env`. Keep the key
   safe: it decrypts signing keys and two-step secrets.
2. In `compose.yaml`, remove `ports:` from `keston-id`, and attach your load
   balancer / reverse proxy to the `keston` network, sending `id.keston.co`
   to `keston-id:4444` and terminating HTTPS. It should pass
   `X-Forwarded-For`.
3. Scale with `docker compose up -d --scale keston-id=3`. Point the load
   balancer's health check at `/readyz`.
4. Back up the `postgres` volume.

For Kubernetes later: the same image, `keston-id clients sync …` as a Job (or
init container), `serve` as a Deployment, `/healthz` and `/readyz` as
liveness and readiness probes.

## Registering an app

Add it to `deploy/clients.json` and run `keston-id clients sync`. Confidential
apps (with a server) name an environment variable holding their secret in
`secretEnv`; leave it out for public apps (single-page or mobile), which must
use PKCE. `verification` is `owned` (The Keston Group's own), `verified`
(a checked partner) or `none` (shows a warning on the consent page).

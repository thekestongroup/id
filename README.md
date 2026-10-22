# Keston ID

OIDC/OAuth2 identity provider for the Keston suite. Built with **Go + fosite** on
the backend and a **Vue** login/consent UI using the
[`@thekestongroup/ui`](https://github.com/thekestongroup/ui) component library.

## Endpoints

| Endpoint | Description |
| --- | --- |
| `/authorize` | OAuth2 / OIDC authorization endpoint |
| `/token` | Token endpoint |
| `/userinfo` | OpenID Connect UserInfo endpoint |
| `/.well-known/jwks.json` | JSON Web Key Set (RS256) |
| `/.well-known/openid-configuration` | OIDC discovery document |
| `/login` | Login page (Vue) |
| `/consent` | Consent page (Vue) |

Issuer: `http://localhost:4444`

## Running

```sh
make build   # installs web deps, builds the Vue UI, then builds the Go binary
./keston-id  # serves on :4444
```

Or, for development, run the two halves separately:

```sh
# terminal 1 — Go server (serves a placeholder until the web build exists)
go run .

# terminal 2 — Vue UI with HMR
cd web && pnpm dev
```

## Demo test app

`demo/` is a browser test client (like the Keston UI demo) that exercises the
service end-to-end: discovery, JWKS, authorization code + PKCE, token exchange
and userinfo. It registers as the public `keston-demo` client.

```sh
# terminal 1 — Keston ID
./keston-id

# terminal 2 — demo test client (http://localhost:3000)
cd demo && pnpm install && pnpm dev
```

Open http://localhost:3000 and click **Sign in with Keston ID**.

## Test client

| Field | Value |
| --- | --- |
| `client_id` | `keston-work` |
| `client_secret` | `keston-work-secret` |
| `redirect_uri` | `http://localhost:3001/callback` |
| `grant_types` | `authorization_code`, `refresh_token` |
| `scopes` | `openid`, `profile`, `email`, `offline_access` |

## Demo user

| Username | Password |
| --- | --- |
| `admin` | `password` |

## Example authorization code flow (with PKCE)

```sh
# 1. Start the flow
curl -i "http://localhost:4444/authorize?client_id=keston-work&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&response_type=code&scope=openid%20profile%20email&state=statevalue123&nonce=noncevalue123&code_challenge=<challenge>&code_challenge_method=S256"

# Follow the redirects: log in with admin/password, then approve consent.
# The final redirect to the client carries ?code=<authorization code>.

# 2. Exchange the code for tokens
curl -u "keston-work:keston-work-secret" \
  -d "grant_type=authorization_code" \
  --data-urlencode "code=<code>" \
  --data-urlencode "redirect_uri=http://localhost:3000/callback" \
  --data-urlencode "code_verifier=<verifier>" \
  http://localhost:4444/token

# 3. Call the UserInfo endpoint
curl -H "Authorization: Bearer <access_token>" http://localhost:4444/userinfo
```

## Configuration

Environment variables (with dev-friendly defaults):

| Variable | Default | Description |
| --- | --- | --- |
| `KESTON_ID_ISSUER` | `http://localhost:4444` | Public issuer URL (discovery, ID/access token `iss`) |
| `KESTON_ID_ADDR` | `:4444` | Listen address |
| `KESTON_ID_SECRET` | dev value | 32-byte HMAC secret for code/refresh tokens |
| `KESTON_ID_RSA_PRIVATE_KEY` | (generated) | PEM RSA key for signing JWTs; set to keep JWT access tokens valid across restarts |
| `KESTON_ID_DATABASE_URL` | (empty → in-memory) | Postgres DSN; when set, clients/users/refresh tokens/codes are persisted |
| `KESTON_ID_WORK_REDIRECT_URI` | `http://localhost:3001/callback` | Registered redirect URI for `keston-work` |
| `KESTON_ID_DEMO_REDIRECT_URI` | `http://localhost:3000/callback` | Registered redirect URI for `keston-demo` |

## Notes

- The UI consumes `@thekestongroup/ui` from GitHub Packages.
- With `KESTON_ID_DATABASE_URL` set, storage is backed by Postgres (schema
  auto-applied on startup). Access tokens are stateless JWTs (not persisted);
  refresh tokens, authorize codes, OIDC/PKCE sessions, clients and users are.
- Without a database URL it falls back to an in-memory store (dev only).
- `web/dist` is committed so `go build` embeds the UI without requiring Node.

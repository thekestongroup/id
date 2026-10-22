export const oidc = {
  issuer: 'http://localhost:4444',
  clientId: 'keston-demo',
  redirectUri: 'http://localhost:3000/callback',
  scope: 'openid profile email',
}

function base64url(buf: Uint8Array): string {
  let binary = ''
  for (const byte of buf) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function randomString(bytes = 32): string {
  const arr = new Uint8Array(bytes)
  crypto.getRandomValues(arr)
  return base64url(arr)
}

async function sha256(input: string): Promise<ArrayBuffer> {
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(input))
}

export async function createCodeChallenge(verifier: string): Promise<string> {
  return base64url(new Uint8Array(await sha256(verifier)))
}

export async function startLogin(): Promise<void> {
  const verifier = randomString()
  const state = randomString()
  const nonce = randomString()

  sessionStorage.setItem('pkce_verifier', verifier)
  sessionStorage.setItem('oidc_state', state)

  const challenge = await createCodeChallenge(verifier)
  const params = new URLSearchParams({
    client_id: oidc.clientId,
    redirect_uri: oidc.redirectUri,
    response_type: 'code',
    scope: oidc.scope,
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  })

  window.location.href = `${oidc.issuer}/authorize?${params.toString()}`
}

export interface TokenResponse {
  access_token: string
  id_token?: string
  refresh_token?: string
  expires_in?: number
  token_type?: string
  scope?: string
}

export async function exchangeCode(code: string): Promise<TokenResponse> {
  const verifier = sessionStorage.getItem('pkce_verifier') ?? ''
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: oidc.redirectUri,
    client_id: oidc.clientId,
    code_verifier: verifier,
  })

  const res = await fetch(`${oidc.issuer}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  })

  if (!res.ok) {
    throw new Error(`token endpoint ${res.status}: ${await res.text()}`)
  }
  return (await res.json()) as TokenResponse
}

export async function fetchUserInfo(accessToken: string): Promise<Record<string, unknown>> {
  const res = await fetch(`${oidc.issuer}/userinfo`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  })
  if (!res.ok) {
    throw new Error(`userinfo endpoint ${res.status}: ${await res.text()}`)
  }
  return (await res.json()) as Record<string, unknown>
}

export async function fetchDiscovery(): Promise<Record<string, unknown>> {
  const res = await fetch(`${oidc.issuer}/.well-known/openid-configuration`)
  if (!res.ok) throw new Error(`discovery ${res.status}: ${await res.text()}`)
  return (await res.json()) as Record<string, unknown>
}

export async function fetchJwks(): Promise<Record<string, unknown>> {
  const res = await fetch(`${oidc.issuer}/.well-known/jwks.json`)
  if (!res.ok) throw new Error(`jwks ${res.status}: ${await res.text()}`)
  return (await res.json()) as Record<string, unknown>
}

export function decodeJwt(token: string): Record<string, unknown> | null {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  try {
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    return JSON.parse(atob(payload)) as Record<string, unknown>
  } catch {
    return null
  }
}

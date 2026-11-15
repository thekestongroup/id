import { api, ApiError, type Flow } from './api'

/**
 * Passkeys and security keys (WebAuthn) in the browser. The server sends
 * options as JSON (binary values in base64url); these turn them into what
 * navigator.credentials wants, and the answer back into JSON.
 */

type Json = Record<string, any>

const fromB64 = (s: string) => {
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '='))
  return Uint8Array.from(b, (c) => c.charCodeAt(0))
}
const toB64 = (buf: ArrayBuffer | ArrayBufferView | null | undefined) => {
  if (!buf) return undefined
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
const descriptors = (list?: Json[]) => list?.map((c) => ({ ...c, id: fromB64(c.id) }))

/** The browser can use passkeys at all. */
export const passkeysSupported = () => typeof window !== 'undefined' && 'PublicKeyCredential' in window

/** The browser can offer passkeys in the email field's autofill. */
export async function autofillSupported() {
  if (!passkeysSupported()) return false
  return (await PublicKeyCredential.isConditionalMediationAvailable?.().catch(() => false)) ?? false
}

function creationOptions(o: Json): PublicKeyCredentialCreationOptions {
  return { ...o, challenge: fromB64(o.challenge), user: { ...o.user, id: fromB64(o.user.id) },
    excludeCredentials: descriptors(o.excludeCredentials) } as unknown as PublicKeyCredentialCreationOptions
}

function requestOptions(o: Json): PublicKeyCredentialRequestOptions {
  return { ...o, challenge: fromB64(o.challenge), allowCredentials: descriptors(o.allowCredentials) } as
    unknown as PublicKeyCredentialRequestOptions
}

function toJSON(c: PublicKeyCredential): Json {
  // Modern browsers do this themselves.
  if (typeof c.toJSON === 'function') return c.toJSON()
  const response: Json = { clientDataJSON: toB64(c.response.clientDataJSON) }
  if (c.response instanceof AuthenticatorAttestationResponse) {
    response.attestationObject = toB64(c.response.attestationObject)
    response.transports = c.response.getTransports?.() ?? []
  } else {
    const r = c.response as AuthenticatorAssertionResponse
    response.authenticatorData = toB64(r.authenticatorData)
    response.signature = toB64(r.signature)
    response.userHandle = toB64(r.userHandle)
  }
  return { id: c.id, rawId: toB64(c.rawId), type: c.type, response,
    authenticatorAttachment: c.authenticatorAttachment ?? undefined,
    clientExtensionResults: c.getClientExtensionResults() }
}

/**
 * Cancelled, or timed out, in the browser's passkey dialog: not an error to
 * show. (Browsers don't say which, on purpose.)
 */
export const cancelled = (e: unknown) =>
  e instanceof DOMException && (e.name === 'NotAllowedError' || e.name === 'AbortError')

/** What went wrong, in words, for anything but a cancel. */
export function passkeyError(e: unknown) {
  if (e instanceof ApiError) return e.message
  if (e instanceof DOMException && e.name === 'InvalidStateError') return 'That passkey is already on your account.'
  if (e instanceof DOMException && e.name === 'SecurityError') return "Passkeys can't be used on this address."
  return "That passkey didn't work. Try again, or use another way."
}

async function get(options: Json, mediation?: CredentialMediationRequirement, signal?: AbortSignal) {
  const c = (await navigator.credentials.get({ publicKey: requestOptions(options), mediation, signal })) as
    PublicKeyCredential | null
  if (!c) throw new DOMException('No passkey chosen', 'NotAllowedError')
  return toJSON(c)
}

/** Add a passkey to the signed-in account. */
export async function addPasskey(name: string, password?: string) {
  const { ceremony, options } = await api.passkeyOptions(password)
  const c = (await navigator.credentials.create({ publicKey: creationOptions(options) })) as PublicKeyCredential | null
  if (!c) throw new DOMException('No passkey made', 'NotAllowedError')
  return api.addPasskey(ceremony, name, toJSON(c))
}

/** The MFA step, with one of this account's passkeys. */
export async function passkeyMfa(authRequestID?: string): Promise<Flow> {
  const { ceremony, options } = await api.mfaPasskeyOptions()
  return api.mfaPasskey(ceremony, await get(options), authRequestID)
}

/**
 * Sign in without a password. With `autofill`, waits for someone to pick a
 * passkey from the email field's suggestions (until the signal aborts).
 */
export async function passkeySignIn(authRequestID?: string, autofill?: AbortSignal): Promise<Flow> {
  const { ceremony, options } = await api.signInPasskeyOptions()
  const credential = await get(options, autofill ? 'conditional' : undefined, autofill)
  return api.signInPasskey(ceremony, credential, authRequestID)
}

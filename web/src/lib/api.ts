/**
 * The Keston ID API (Go server, /api). Same origin, so the session cookie
 * goes with every request; changes carry X-Keston-ID, which the server
 * requires as CSRF protection.
 */

export type Verification = 'owned' | 'verified' | 'none'

export interface ClientView {
  id: string
  name: string
  publisher: string
  verification: Verification
  privacyUrl: string
  termsUrl: string
  /** Where people are sent back to, e.g. "learn.keston.co". */
  redirectHost?: string
}

export interface ScopeInfo {
  id: string
  label: string
  description: string
  /** Lucide icon name, see scopes.ts. */
  icon: string
}

export interface UserView {
  id: string
  name: string
  email: string
  organisation: string
  /** Profile picture URL, if they have one. */
  avatar?: string
}

/** One thing a new password must meet (the organisation's policy). `min` is how many; "common" is checked by the server only. */
export interface PasswordRule {
  id: 'length' | 'uppercase' | 'lowercase' | 'digits' | 'special' | 'common'
  label: string
  baseline: boolean
  min?: number
}

/** Things someone must do before they're fully signed in: choose a new password, set up MFA. */
export type RequiredAction = 'password' | 'mfa'

/** What the sign-in flow shows next. */
export interface Flow {
  step: 'sign-in' | 'choose' | 'mfa' | 'actions' | 'consent' | 'redirect' | 'account'
  /** step 'actions': what's left, in order. */
  actions?: RequiredAction[]
  redirect?: string
  client?: ClientView
  scopes?: { required: ScopeInfo[]; optional: ScopeInfo[] }
  user?: UserView
  /** At the MFA step: the ways this account can do it. */
  mfa?: { app: boolean; passkey: boolean }
  /** step 'actions' with MFA: it can be put off ("Not now") until then. */
  mfaGraceUntil?: string
  /** step 'actions' with a new password: what it must meet. */
  passwordRules?: PasswordRule[]
}

/** A passkey or security key on the account. */
export interface Passkey {
  id: string
  name: string
  createdAt: string
  lastUsedAt?: string
  /** Synced between devices by a password manager, rather than kept on one device or security key. */
  synced: boolean
}

/** A WebAuthn ceremony the browser answers: its token and the options for navigator.credentials. */
export interface PasskeyCeremony {
  ceremony: string
  options: Record<string, any>
}

/** Which profile fields this person may change (their organisation decides). */
export interface Editable {
  name: boolean
  email: boolean
  picture: boolean
}

export interface Me {
  user: UserView
  username: string
  domain: string
  editable: Editable
  security: {
    /** MFA is on: an authenticator app, or any passkey. */
    mfa: boolean
    authenticatorApp: boolean
    passkeys: number
    backupCodesLeft: number
    passwordChangedAt: string
    /** What a new password must meet (their organisation's policy). */
    passwordRules?: PasswordRule[]
  }
}

export interface ConnectedApp {
  client: ClientView
  /** forced: on, and can't be removed; enabled: on, can be removed (both set by your organisation); user: added by you. */
  source: 'forced' | 'enabled' | 'user'
  removable: boolean
  scopes: ScopeInfo[]
  /** When you allowed it; missing if you haven't signed in to it yet. */
  grantedAt?: string
}

export interface AppRequest {
  id: string
  clientId: string
  appName: string
  reason: string
  status: 'pending' | 'approved' | 'declined' | 'cancelled'
  decisionMessage: string
  decidedByName: string
  decidedAt?: string
  seen: boolean
  createdAt: string
}

export interface SessionInfo {
  id: string
  userAgent: string
  ip: string
  createdAt: string
  lastSeenAt: string
  current: boolean
}

/** An account signed in to this browser. */
export interface SignedInAccount {
  id: string
  name: string
  email: string
  organisation: string
  /** Profile picture URL, if they have one. */
  avatar?: string
  active: boolean
  needsMfa: boolean
}

/** A guest membership: an invitation to be a guest in another organisation, or a guest there. */
export interface Guest {
  id: string
  organisationId: string
  organisationName: string
  organisationDomain: string
  homeOrganisationName: string
  /** pending (an invitation), accepted… */
  status: string
  invitedByName: string
  createdAt: string
  /** Their organisation allows guests now; if not, it's on hold. */
  active: boolean
}

export interface Prompts {
  guestInvitations: (Guest & { popup: boolean })[]
}

export interface Notification {
  id: string
  type: 'info' | 'success' | 'warning' | 'error'
  title: string
  body: string
  link: string
  readAt?: string
  createdAt: string
}

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  /** The form field the error belongs to, if any. */
  readonly field?: string
  /** The rest of the response, e.g. which app a sign-in refusal is about. */
  readonly data?: Record<string, unknown>

  constructor(status: number, code: string, message: string, field?: string, data?: Record<string, unknown>) {
    super(message)
    this.status = status
    this.code = code
    this.field = field
    this.data = data
  }
}

/**
 * Calls Keston ID: the sign-in flow at /api (before you're signed in), and
 * Keston ID's API at /v1 (the same one Keston Admin and apps use), here with
 * the session cookie. path is absolute.
 */
async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  let res: Response
  try {
    res = await fetch(path, {
      method,
      credentials: 'same-origin',
      headers: method === 'GET' ? {} : { 'Content-Type': 'application/json', 'X-Keston-ID': '1' },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  } catch {
    throw new ApiError(0, 'network', "Couldn't reach Keston ID. Check your connection and try again.")
  }
  if (res.status === 204) return undefined as T
  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    throw new ApiError(res.status, data.error ?? 'error', data.message ?? 'Something went wrong. Try again.', data.field, data)
  }
  return data as T
}

export const api = {
  prompts: () => request<Prompts>('GET', '/v1/prompts'),
  promptSeen: (id: string) => request<void>('POST', '/v1/prompts/seen', { kind: 'guest_invitation', id }),
  respondToInvitation: (id: string, accept: boolean) =>
    request<Guest>('POST', `/v1/guest-invitations/${encodeURIComponent(id)}/${accept ? 'accept' : 'decline'}`, {}),
  guestMemberships: () => request<Guest[]>('GET', '/v1/guest-memberships'),
  leaveGuest: (id: string) => request<void>('POST', `/v1/guest-memberships/${encodeURIComponent(id)}/leave`, {}),
  notifications: () => request<Notification[]>('GET', '/v1/notifications'),
  readNotifications: () => request<void>('POST', '/v1/notifications/read', {}),
  clearNotifications: () => request<void>('DELETE', '/v1/notifications', {}),
  flow: (authRequestID?: string) =>
    request<Flow>('GET', `/api/flow${authRequestID ? `?authRequestID=${encodeURIComponent(authRequestID)}` : ''}`),
  signIn: (email: string, password: string, authRequestID?: string) =>
    request<Flow>('POST', '/api/sign-in', { email, password, authRequestID }),
  mfa: (code: string, kind: 'app' | 'backup', authRequestID?: string) =>
    request<Flow>('POST', '/api/mfa', { code, kind, authRequestID }),
  /** Signing in with a temporary access pass from an admin, instead of a password and MFA. */
  signInWithPass: (email: string, code: string, authRequestID?: string) =>
    request<Flow>('POST', '/api/sign-in/access-pass', { email, code, authRequestID }),
  /** Required actions, during sign-in. */
  requiredPassword: (next: string, authRequestID?: string) =>
    request<Flow>('POST', '/api/required/password', { new: next, authRequestID }),
  requiredMfaSetup: () =>
    request<{ secret: string; otpauthUrl: string; qrCode: string }>('POST', '/api/required/mfa/setup', {}),
  /** "Not now", during the organisation's grace period. */
  requiredMfaSkip: (authRequestID?: string) => request<Flow>('POST', '/api/required/mfa/skip', { authRequestID }),
  requiredMfaEnable: (code: string, authRequestID?: string) =>
    request<{ backupCodes: string[]; flow: Flow }>('POST', '/api/required/mfa/enable', { code, authRequestID }),
  consent: (authRequestID: string, scopes: string[]) =>
    request<Flow>('POST', '/api/consent', { authRequestID, scopes }),
  /** Signs the active account (or every account) out of Keston ID and its apps. */
  signOut: (all = false) => request<{ remaining: number }>('POST', '/api/sign-out', { all }),
  accounts: () => request<SignedInAccount[]>('GET', '/api/accounts'),
  switchAccount: (id: string, authRequestID?: string) =>
    request<Flow>('POST', '/api/accounts/switch', { id, authRequestID }),

  me: () => request<Me>('GET', '/v1/me'),
  updateProfile: (changes: { name?: string; username?: string }) => request<UserView>('PATCH', '/v1/me', changes),
  removePicture: () => request<void>('DELETE', '/v1/me/picture', {}),
  /** Uploads a profile picture (PNG, JPEG or GIF, under 2 MB). */
  setPicture: async (file: File): Promise<UserView> => {
    const res = await fetch('/v1/me/picture', {
      method: 'PUT',
      credentials: 'same-origin',
      headers: { 'Content-Type': file.type || 'application/octet-stream', 'X-Keston-ID': '1' },
      body: file,
    }).catch(() => {
      throw new ApiError(0, 'network', "Couldn't reach Keston ID. Check your connection and try again.")
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new ApiError(res.status, data.error ?? 'error', data.message ?? 'Something went wrong.', data.field)
    return data as UserView
  },
  apps: () => request<ConnectedApp[]>('GET', '/v1/me/apps'),
  revokeApp: (clientId: string) => request<void>('DELETE', `/v1/me/apps/${encodeURIComponent(clientId)}`, {}),
  requestableApps: () => request<ClientView[]>('GET', '/v1/me/requestable-apps'),
  appRequests: () => request<AppRequest[]>('GET', '/v1/me/app-requests'),
  requestApp: (clientId: string, reason: string) => request<AppRequest>('POST', '/v1/me/app-requests', { clientId, reason }),
  cancelAppRequest: (id: string) => request<void>('DELETE', `/v1/me/app-requests/${encodeURIComponent(id)}`, {}),
  appRequestsSeen: () => request<void>('POST', '/v1/me/app-requests/seen', {}),
  sessions: () => request<SessionInfo[]>('GET', '/v1/me/sessions'),
  endSession: (id: string) => request<void>('DELETE', `/v1/me/sessions/${encodeURIComponent(id)}`, {}),
  changePassword: (current: string, next: string) => request<void>('POST', '/v1/me/password', { current, new: next }),
  /** A new authenticator secret (not on until confirmed), with its QR code as a data URI. */
  mfaSetup: () =>
    request<{ secret: string; otpauthUrl: string; qrCode: string }>('POST', '/v1/me/mfa/setup', {}),
  mfaEnable: (code: string) => request<{ backupCodes: string[] }>('POST', '/v1/me/mfa/enable', { code }),
  mfaDisable: (password: string) => request<void>('POST', '/v1/me/mfa/disable', { password }),

  // Passkeys and security keys (see passkeys.ts for the browser side).
  signInPasskeyOptions: () => request<PasskeyCeremony>('POST', '/api/sign-in/passkey/options', {}),
  signInPasskey: (ceremony: string, credential: unknown, authRequestID?: string) =>
    request<Flow>('POST', '/api/sign-in/passkey', { ceremony, credential, authRequestID }),
  mfaPasskeyOptions: () => request<PasskeyCeremony>('POST', '/api/mfa/passkey/options', {}),
  mfaPasskey: (ceremony: string, credential: unknown, authRequestID?: string) =>
    request<Flow>('POST', '/api/mfa/passkey', { ceremony, credential, authRequestID }),
  passkeys: () => request<Passkey[]>('GET', '/v1/me/passkeys'),
  /** Starts adding one. Without a recent sign-in, needs the password (error code "reauthenticate"). */
  passkeyOptions: (password?: string) => request<PasskeyCeremony>('POST', '/v1/me/passkeys/options', { password }),
  addPasskey: (ceremony: string, name: string, credential: unknown) =>
    request<Passkey>('POST', '/v1/me/passkeys', { ceremony, name, credential }),
  renamePasskey: (id: string, name: string) =>
    request<Passkey>('PATCH', `/v1/me/passkeys/${encodeURIComponent(id)}`, { name }),
  removePasskey: (id: string) => request<void>('DELETE', `/v1/me/passkeys/${encodeURIComponent(id)}`, {}),
}

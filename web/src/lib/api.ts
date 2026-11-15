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
  security: { mfa: boolean; backupCodesLeft: number; passwordChangedAt: string }
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

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  /** The form field the error belongs to, if any. */
  readonly field?: string

  constructor(status: number, code: string, message: string, field?: string) {
    super(message)
    this.status = status
    this.code = code
    this.field = field
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  let res: Response
  try {
    res = await fetch(`/api${path}`, {
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
    throw new ApiError(res.status, data.error ?? 'error', data.message ?? 'Something went wrong. Try again.', data.field)
  }
  return data as T
}

export const api = {
  flow: (authRequestID?: string) =>
    request<Flow>('GET', `/flow${authRequestID ? `?authRequestID=${encodeURIComponent(authRequestID)}` : ''}`),
  signIn: (email: string, password: string, authRequestID?: string) =>
    request<Flow>('POST', '/sign-in', { email, password, authRequestID }),
  mfa: (code: string, kind: 'app' | 'backup', authRequestID?: string) =>
    request<Flow>('POST', '/mfa', { code, kind, authRequestID }),
  /** Signing in with a temporary access pass from an admin, instead of a password and MFA. */
  signInWithPass: (email: string, code: string, authRequestID?: string) =>
    request<Flow>('POST', '/sign-in/access-pass', { email, code, authRequestID }),
  /** Required actions, during sign-in. */
  requiredPassword: (next: string, authRequestID?: string) =>
    request<Flow>('POST', '/required/password', { new: next, authRequestID }),
  requiredMfaSetup: () =>
    request<{ secret: string; otpauthUrl: string; qrCode: string }>('POST', '/required/mfa/setup', {}),
  requiredMfaEnable: (code: string, authRequestID?: string) =>
    request<{ backupCodes: string[]; flow: Flow }>('POST', '/required/mfa/enable', { code, authRequestID }),
  consent: (authRequestID: string, scopes: string[]) =>
    request<Flow>('POST', '/consent', { authRequestID, scopes }),
  /** Signs the active account (or every account) out of Keston ID and its apps. */
  signOut: (all = false) => request<{ remaining: number }>('POST', '/sign-out', { all }),
  accounts: () => request<SignedInAccount[]>('GET', '/accounts'),
  switchAccount: (id: string, authRequestID?: string) =>
    request<Flow>('POST', '/accounts/switch', { id, authRequestID }),

  me: () => request<Me>('GET', '/me'),
  updateProfile: (changes: { name?: string; username?: string }) => request<UserView>('PATCH', '/me', changes),
  removePicture: () => request<void>('DELETE', '/me/picture', {}),
  /** Uploads a profile picture (PNG, JPEG or GIF, under 2 MB). */
  setPicture: async (file: File): Promise<UserView> => {
    const res = await fetch('/api/me/picture', {
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
  apps: () => request<ConnectedApp[]>('GET', '/me/apps'),
  revokeApp: (clientId: string) => request<void>('DELETE', `/me/apps/${encodeURIComponent(clientId)}`, {}),
  sessions: () => request<SessionInfo[]>('GET', '/me/sessions'),
  endSession: (id: string) => request<void>('DELETE', `/me/sessions/${encodeURIComponent(id)}`, {}),
  changePassword: (current: string, next: string) => request<void>('POST', '/me/password', { current, new: next }),
  /** A new authenticator secret (not on until confirmed), with its QR code as a data URI. */
  mfaSetup: () =>
    request<{ secret: string; otpauthUrl: string; qrCode: string }>('POST', '/me/mfa/setup', {}),
  mfaEnable: (code: string) => request<{ backupCodes: string[] }>('POST', '/me/mfa/enable', { code }),
  mfaDisable: (password: string) => request<void>('POST', '/me/mfa/disable', { password }),
}

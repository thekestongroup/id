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
}

/** What the sign-in flow shows next. */
export interface Flow {
  step: 'sign-in' | 'two-step' | 'consent' | 'redirect' | 'account'
  redirect?: string
  client?: ClientView
  scopes?: { required: ScopeInfo[]; optional: ScopeInfo[] }
  user?: UserView
}

export interface Me {
  user: UserView
  security: { twoStep: boolean; backupCodesLeft: number; passwordChangedAt: string }
}

export interface ConnectedApp {
  client: ClientView
  scopes: ScopeInfo[]
  grantedAt: string
}

export interface SessionInfo {
  id: string
  userAgent: string
  ip: string
  createdAt: string
  lastSeenAt: string
  current: boolean
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
  twoStep: (code: string, kind: 'app' | 'backup', authRequestID?: string) =>
    request<Flow>('POST', '/two-step', { code, kind, authRequestID }),
  consent: (authRequestID: string, scopes: string[]) =>
    request<Flow>('POST', '/consent', { authRequestID, scopes }),
  signOut: () => request<void>('POST', '/sign-out', {}),

  me: () => request<Me>('GET', '/me'),
  apps: () => request<ConnectedApp[]>('GET', '/me/apps'),
  revokeApp: (clientId: string) => request<void>('DELETE', `/me/apps/${encodeURIComponent(clientId)}`, {}),
  sessions: () => request<SessionInfo[]>('GET', '/me/sessions'),
  endSession: (id: string) => request<void>('DELETE', `/me/sessions/${encodeURIComponent(id)}`, {}),
  changePassword: (current: string, next: string) => request<void>('POST', '/me/password', { current, new: next }),
  twoStepSetup: () => request<{ secret: string; otpauthUrl: string }>('POST', '/me/two-step/setup', {}),
  twoStepEnable: (code: string) => request<{ backupCodes: string[] }>('POST', '/me/two-step/enable', { code }),
  twoStepDisable: (password: string) => request<void>('POST', '/me/two-step/disable', { password }),
}

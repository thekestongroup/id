import { ref } from 'vue'
import type { Router } from 'vue-router'
import { api, ApiError, type Flow, type Me } from './api'

/** The signed-in account, loaded once for the account pages. */
export const me = ref<Me>()

export async function loadMe(force = false): Promise<Me | undefined> {
  if (me.value && !force) return me.value
  try {
    me.value = await api.me()
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) me.value = undefined
    else throw e
  }
  return me.value
}

export async function signOut(router: Router) {
  await api.signOut().catch(() => {})
  me.value = undefined
  router.push('/sign-in')
}

/**
 * Go to wherever the server says the flow goes next. "redirect" leaves the
 * web UI: back to the app (through /authorize/callback) with a full page load.
 */
export async function follow(router: Router, flow: Flow, authRequestID?: string) {
  const query = authRequestID ? { authRequestID } : {}
  switch (flow.step) {
    case 'redirect':
      window.location.assign(flow.redirect!)
      return
    case 'account':
      await loadMe(true)
      return router.replace('/account')
    case 'consent':
      return router.replace({ path: '/consent', query })
    case 'two-step':
      return router.replace({ path: '/two-step', query })
    default:
      return router.replace({ path: '/sign-in', query })
  }
}

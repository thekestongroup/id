import { nextTick } from 'vue'
import { createRouter, createWebHistory } from 'vue-router'
import { loadMe } from './lib/session'

declare module 'vue-router' {
  interface RouteMeta {
    title?: string
    /** Only once fully signed in (both steps). */
    requiresAuth?: boolean
  }
}

/**
 * The OAuth endpoints (/authorize, /oauth/token, …) are the Go server's.
 * /authorize sends people here, to /sign-in?authRequestID=…, and each page
 * asks the server (/api/flow) what comes next.
 */
export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', redirect: '/account' },
    { path: '/sign-in', component: () => import('./pages/SignIn.vue'), meta: { title: 'Sign in' } },
    {
      path: '/choose-account',
      component: () => import('./pages/ChooseAccount.vue'),
      meta: { title: 'Choose an account' },
    },
    { path: '/two-step', redirect: (to) => ({ path: '/mfa', query: to.query }) },
    { path: '/mfa', component: () => import('./pages/Mfa.vue'), meta: { title: "Check it's you" } },
    {
      path: '/required',
      component: () => import('./pages/RequiredActions.vue'),
      meta: { title: 'Before you continue' },
    },
    {
      path: '/access-pass',
      component: () => import('./pages/AccessPass.vue'),
      meta: { title: 'Sign in with an access pass' },
    },
    { path: '/consent', component: () => import('./pages/Consent.vue'), meta: { title: 'Allow access' } },
    {
      path: '/forgot-password',
      component: () => import('./pages/ForgotPassword.vue'),
      meta: { title: 'Forgotten your password?' },
    },
    { path: '/signed-out', component: () => import('./pages/SignedOut.vue'), meta: { title: 'Signed out' } },
    {
      path: '/account',
      component: () => import('./pages/account/AccountLayout.vue'),
      meta: { requiresAuth: true },
      children: [
        { path: '', component: () => import('./pages/account/Overview.vue'), meta: { title: 'Your account' } },
        { path: 'security', component: () => import('./pages/account/Security.vue'), meta: { title: 'Security' } },
        { path: 'apps', component: () => import('./pages/account/ConnectedApps.vue'), meta: { title: 'Connected apps' } },
      ],
    },
    { path: '/:pathMatch(.*)*', redirect: '/account' },
  ],
})

router.beforeEach(async (to) => {
  if (to.meta.requiresAuth && !(await loadMe())) return '/sign-in'
})

// A new page: name the tab and move focus to its heading, so screen readers
// start from the top, as they would after a full page load.
router.afterEach((to, from) => {
  document.title = to.meta.title ? `${to.meta.title} – Keston ID` : 'Keston ID'
  if (!from.matched.length) return
  nextTick(() => {
    // Sign-in pages make their h1 focusable; account pages focus <main>.
    const target =
      document.querySelector<HTMLElement>('main h1[tabindex]') ?? document.querySelector<HTMLElement>('main[tabindex]')
    target?.focus({ preventScroll: true })
  })
})

import type { Router } from 'vue-router'

/**
 * After a new version is deployed, a tab opened before it still asks for
 * the old version's page files, which are gone, so moving to another page
 * fails. When that happens, load the page afresh (at most once a minute, so
 * a real outage doesn't reload forever).
 */
export function reloadOnStaleBuild(router: Router) {
  const KEY = 'keston-stale-build-reload'
  const reload = (to?: string) => {
    try {
      const last = Number(sessionStorage.getItem(KEY) ?? 0)
      if (Date.now() - last < 60_000) return false
      sessionStorage.setItem(KEY, String(Date.now()))
    } catch {
      // No storage: reload anyway.
    }
    if (to) window.location.assign(to)
    else window.location.reload()
    return true
  }
  // A preload of a page's files failed.
  window.addEventListener('vite:preloadError', (event) => {
    if (reload()) event.preventDefault()
  })
  // Loading the next page's code failed.
  router.onError((error, to) => {
    const message = error instanceof Error ? error.message : String(error)
    if (/dynamically imported module|Importing a module script failed|error loading dynamically|MIME type/i.test(message))
      reload(to.fullPath)
  })
}

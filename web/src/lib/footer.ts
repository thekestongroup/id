import type { FooterProps } from '@thekestongroup/ui'

/** The footer's name, version and build, the same on every page. The last two are put in at build time (see vite.config.ts). */
export const footer: FooterProps = {
  appName: 'Keston ID',
  version: __APP_VERSION__,
  build: __APP_BUILD__ || undefined,
}

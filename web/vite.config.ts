import tailwindcss from '@tailwindcss/vite'
import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vite'
import pkg from './package.json' with { type: 'json' }

// What the footer shows: the version from package.json, and the build (the commit, from CI, or the
// APP_BUILD build argument in Docker). Empty on a local run.
const build = (process.env.APP_BUILD ?? process.env.GITHUB_SHA ?? '').slice(0, 7)

export default defineConfig({
  plugins: [vue(), tailwindcss()],
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
    __APP_BUILD__: JSON.stringify(build),
  },
  server: { port: 5180 },
})

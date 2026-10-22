import tailwindcss from '@tailwindcss/vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'

// Test client for Keston ID. Runs on :3000 (the registered redirect_uri) and
// consumes the Keston UI library from source while it is unpublished.
export default defineConfig({
  plugins: [vue(), tailwindcss()],
  server: {
    port: 3000,
  },
  resolve: {
    alias: {
      '@thekestongroup/ui': fileURLToPath(new URL('../../ui/src', import.meta.url)),
    },
  },
})

import tailwindcss from '@tailwindcss/vite'
import vue from '@vitejs/plugin-vue'
import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'

// Consume the Keston UI library from source while it is not yet published.
// https://vite.dev/config/
export default defineConfig({
  plugins: [vue(), tailwindcss()],
  resolve: {
    alias: {
      '@thekestongroup/ui': fileURLToPath(new URL('../../ui/src', import.meta.url)),
    },
  },
})

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import Button from '@thekestongroup/ui/components/Button.vue'
import { fetchDiscovery, fetchJwks, oidc, startLogin } from '../lib/oidc'

type Status = 'loading' | 'ok' | 'error'

const discovery = ref<Record<string, unknown> | null>(null)
const discoveryStatus = ref<Status>('loading')
const discoveryError = ref('')

const jwks = ref<Record<string, unknown> | null>(null)
const jwksStatus = ref<Status>('loading')
const jwksError = ref('')

async function runDiscovery() {
  discoveryStatus.value = 'loading'
  try {
    discovery.value = await fetchDiscovery()
    discoveryStatus.value = 'ok'
  } catch (e) {
    discoveryError.value = String(e)
    discoveryStatus.value = 'error'
  }
}

async function runJwks() {
  jwksStatus.value = 'loading'
  try {
    jwks.value = await fetchJwks()
    jwksStatus.value = 'ok'
  } catch (e) {
    jwksError.value = String(e)
    jwksStatus.value = 'error'
  }
}

onMounted(() => {
  runDiscovery()
  runJwks()
})
</script>

<template>
  <div class="min-h-screen bg-neutral-100 text-neutral-900">
    <div class="mx-auto max-w-3xl space-y-8 px-6 py-12">
      <header>
        <h1 class="text-3xl font-bold">Keston ID — Service Demo</h1>
        <p class="mt-2 text-neutral-500">
          Test client that exercises the Keston ID OIDC service (discovery, JWKS, authorization code + PKCE, token, userinfo).
        </p>
      </header>

      <section class="rounded-lg border border-neutral-200 bg-white p-6">
        <h2 class="text-lg font-semibold">Client configuration</h2>
        <dl class="mt-4 grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
          <div><dt class="text-neutral-500">Issuer</dt><dd class="font-mono">{{ oidc.issuer }}</dd></div>
          <div><dt class="text-neutral-500">Client ID</dt><dd class="font-mono">{{ oidc.clientId }}</dd></div>
          <div><dt class="text-neutral-500">Redirect URI</dt><dd class="font-mono">{{ oidc.redirectUri }}</dd></div>
          <div><dt class="text-neutral-500">Scope</dt><dd class="font-mono">{{ oidc.scope }}</dd></div>
        </dl>
      </section>

      <section class="rounded-lg border border-neutral-200 bg-white p-6">
        <div class="flex items-center justify-between">
          <h2 class="text-lg font-semibold">Discovery document</h2>
          <Button variant="outline" size="sm" @click="runDiscovery">Re-run</Button>
        </div>
        <p v-if="discoveryStatus === 'loading'" class="mt-3 text-sm text-neutral-500">Fetching…</p>
        <p v-else-if="discoveryStatus === 'error'" class="mt-3 text-sm text-red-600">{{ discoveryError }}</p>
        <pre v-else class="mt-3 max-h-72 overflow-auto rounded bg-neutral-50 p-3 text-xs">{{ JSON.stringify(discovery, null, 2) }}</pre>
      </section>

      <section class="rounded-lg border border-neutral-200 bg-white p-6">
        <div class="flex items-center justify-between">
          <h2 class="text-lg font-semibold">JSON Web Key Set</h2>
          <Button variant="outline" size="sm" @click="runJwks">Re-run</Button>
        </div>
        <p v-if="jwksStatus === 'loading'" class="mt-3 text-sm text-neutral-500">Fetching…</p>
        <p v-else-if="jwksStatus === 'error'" class="mt-3 text-sm text-red-600">{{ jwksError }}</p>
        <pre v-else class="mt-3 max-h-72 overflow-auto rounded bg-neutral-50 p-3 text-xs">{{ JSON.stringify(jwks, null, 2) }}</pre>
      </section>

      <section class="rounded-lg border border-neutral-200 bg-white p-6">
        <h2 class="text-lg font-semibold">Authorization code flow (PKCE)</h2>
        <p class="mt-2 text-sm text-neutral-500">
          Signs in with <span class="font-mono">admin / password</span> and returns an access token, ID token and userinfo.
        </p>
        <Button class="mt-4" @click="startLogin">Sign in with Keston ID</Button>
      </section>
    </div>
  </div>
</template>

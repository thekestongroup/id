<script setup lang="ts">
import { onMounted, ref } from 'vue'
import Button from '@thekestongroup/ui/components/Button.vue'
import { decodeJwt, exchangeCode, fetchUserInfo, type TokenResponse } from '../lib/oidc'

type Status = 'working' | 'done' | 'error'

const status = ref<Status>('working')
const error = ref('')
const tokens = ref<TokenResponse | null>(null)
const idTokenClaims = ref<Record<string, unknown> | null>(null)
const userinfo = ref<Record<string, unknown> | null>(null)

onMounted(async () => {
  try {
    const params = new URLSearchParams(window.location.search)
    const code = params.get('code')
    const state = params.get('state')
    const expectedState = sessionStorage.getItem('oidc_state')
    const oauthError = params.get('error')

    if (oauthError) {
      status.value = 'error'
      error.value = `${oauthError}: ${params.get('error_description') ?? ''}`
      return
    }
    if (state !== expectedState) {
      status.value = 'error'
      error.value = 'State mismatch — possible CSRF attack.'
      return
    }
    if (!code) {
      status.value = 'error'
      error.value = 'No authorization code returned.'
      return
    }

    tokens.value = await exchangeCode(code)
    idTokenClaims.value = tokens.value.id_token ? decodeJwt(tokens.value.id_token) : null
    userinfo.value = await fetchUserInfo(tokens.value.access_token)
    status.value = 'done'
  } catch (e) {
    status.value = 'error'
    error.value = String(e)
  }
})

function reset() {
  sessionStorage.removeItem('pkce_verifier')
  sessionStorage.removeItem('oidc_state')
  window.location.href = '/'
}
</script>

<template>
  <div class="min-h-screen bg-neutral-100 text-neutral-900">
    <div class="mx-auto max-w-3xl space-y-6 px-6 py-12">
      <header>
        <h1 class="text-3xl font-bold">Keston ID — Callback</h1>
      </header>

      <section v-if="status === 'working'" class="rounded-lg border border-neutral-200 bg-white p-6">
        <p class="text-sm text-neutral-500">Exchanging authorization code and fetching userinfo…</p>
      </section>

      <section v-else-if="status === 'error'" class="rounded-lg border border-red-200 bg-white p-6">
        <p class="text-sm text-red-600">Flow failed: {{ error }}</p>
        <Button class="mt-4" @click="reset">Back to demo</Button>
      </section>

      <template v-else>
        <section class="rounded-lg border border-neutral-200 bg-white p-6">
          <h2 class="text-lg font-semibold">Access token</h2>
          <pre class="mt-3 overflow-auto rounded bg-neutral-50 p-3 text-xs">{{ tokens?.access_token }}</pre>
          <dl v-if="tokens" class="mt-3 grid grid-cols-2 gap-2 text-sm">
            <div><dt class="text-neutral-500">Token type</dt><dd class="font-mono">{{ tokens.token_type }}</dd></div>
            <div><dt class="text-neutral-500">Expires in</dt><dd class="font-mono">{{ tokens.expires_in }}s</dd></div>
            <div><dt class="text-neutral-500">Scope</dt><dd class="font-mono">{{ tokens.scope }}</dd></div>
          </dl>
        </section>

        <section v-if="tokens?.id_token" class="rounded-lg border border-neutral-200 bg-white p-6">
          <h2 class="text-lg font-semibold">ID token (decoded claims)</h2>
          <pre class="mt-3 overflow-auto rounded bg-neutral-50 p-3 text-xs">{{ JSON.stringify(idTokenClaims, null, 2) }}</pre>
        </section>

        <section class="rounded-lg border border-neutral-200 bg-white p-6">
          <h2 class="text-lg font-semibold">Userinfo</h2>
          <pre class="mt-3 overflow-auto rounded bg-neutral-50 p-3 text-xs">{{ JSON.stringify(userinfo, null, 2) }}</pre>
        </section>

        <section class="flex gap-3">
          <Button @click="reset">Back to demo</Button>
        </section>
      </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import Button from '@thekestongroup/ui/components/Button.vue'

const params = new URLSearchParams(window.location.search)
const returnTo = params.get('return_to') ?? ''

const authParams = new URLSearchParams(returnTo.includes('?') ? returnTo.split('?')[1] : '')
const clientId = authParams.get('client_id') ?? ''
const scopes = (authParams.get('scope') ?? '').split(' ').filter(Boolean)
</script>

<template>
  <div class="flex min-h-screen items-center justify-center bg-neutral-100 px-4">
    <div class="w-full max-w-sm rounded-lg border border-neutral-200 bg-white p-8 shadow-sm">
      <h1 class="text-2xl font-bold text-neutral-900">Keston ID</h1>
      <p class="mt-3 text-sm text-neutral-500">
        <span class="font-medium text-neutral-700">{{ clientId }}</span> is requesting access to your account.
      </p>

      <div class="mt-6">
        <p class="text-sm font-medium text-neutral-700">Requested scopes</p>
        <ul class="mt-2 space-y-1">
          <li v-for="scope in scopes" :key="scope" class="text-sm text-neutral-500">{{ scope }}</li>
        </ul>
      </div>

      <form method="post" action="/consent" class="mt-8 flex gap-3">
        <input type="hidden" name="return_to" :value="returnTo" />
        <Button type="submit" name="action" value="deny" variant="outline" class="flex-1">Deny</Button>
        <Button type="submit" name="action" value="allow" class="flex-1">Allow</Button>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { Button } from '@thekestongroup/ui'

interface Account {
  username: string
  sid: string
  active: boolean
}

const accounts = ref<Account[]>([])

onMounted(async () => {
  try {
    const res = await fetch('/api/accounts')
    const data = await res.json()
    accounts.value = data.accounts ?? []
  } catch {
    accounts.value = []
  }
})
</script>

<template>
  <div class="flex min-h-screen items-center justify-center bg-neutral-100 px-4">
    <div class="w-full max-w-sm rounded-lg border border-neutral-200 bg-white p-6 shadow-sm">
      <h1 class="text-xl font-bold text-neutral-900">Choose an account</h1>
      <p class="mt-1 text-sm text-neutral-500">Signed in to Keston ID.</p>

      <p v-if="accounts.length === 0" class="mt-6 text-sm text-neutral-500">
        You're not signed in to any accounts.
      </p>

      <ul v-else class="mt-4 divide-y divide-neutral-100">
        <li v-for="account in accounts" :key="account.sid" class="flex items-center justify-between py-3">
          <div class="flex items-center gap-2">
            <span class="text-sm font-medium text-neutral-900">{{ account.username }}</span>
            <span v-if="account.active" class="rounded bg-blue-100 px-1.5 py-0.5 text-xs text-blue-700">
              Active
            </span>
          </div>
          <form method="post" action="/logout">
            <input type="hidden" name="sid" :value="account.sid" />
            <Button type="submit" variant="outline" size="sm">Sign out</Button>
          </form>
        </li>
      </ul>

      <div class="mt-6 space-y-2 border-t border-neutral-100 pt-4">
        <a href="/login" class="block text-sm text-blue-600 hover:underline">Add another account</a>
        <a href="/" class="block text-sm text-blue-600 hover:underline">Done</a>
        <form v-if="accounts.length" method="post" action="/logout">
          <input type="hidden" name="action" value="all" />
          <Button type="submit" variant="ghost" size="sm">Sign out all accounts</Button>
        </form>
      </div>
    </div>
  </div>
</template>

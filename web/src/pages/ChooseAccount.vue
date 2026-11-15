<script setup lang="ts">
import { ChevronRight, LogOut, UserPlus } from '@lucide/vue'
import { Avatar, Badge, Button, Card, Divider, Spinner } from '@thekestongroup/ui'
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import AppName from '../components/AppName.vue'
import KestonIdPage from '../components/KestonIdPage.vue'
import { api, type ClientView, type SignedInAccount } from '../lib/api'
import { follow, signOut } from '../lib/session'

/**
 * Choose an account: every account signed in to this browser (even just
 * one), "Use a different account", and "Sign out of all accounts". During an
 * app's sign-in (?authRequestID), choosing one carries on to the app.
 */
const route = useRoute()
const router = useRouter()
const authRequestID = computed(() => (route.query.authRequestID as string | undefined) || undefined)

const accounts = ref<SignedInAccount[]>()
const client = ref<ClientView>()
const choosing = ref<string>()
const error = ref<string>()

onMounted(async () => {
  const [list, flow] = await Promise.all([api.accounts(), authRequestID.value ? api.flow(authRequestID.value) : undefined])
  if (!list.length) {
    router.replace({ path: '/sign-in', query: authRequestID.value ? { authRequestID: authRequestID.value } : {} })
    return
  }
  accounts.value = list
  client.value = flow?.client
})

async function choose(account: SignedInAccount) {
  choosing.value = account.id
  error.value = undefined
  try {
    await follow(router, await api.switchAccount(account.id, authRequestID.value), authRequestID.value)
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
    choosing.value = undefined
  }
}

function useAnother() {
  router.push({ path: '/sign-in', query: { add: '1', ...(authRequestID.value ? { authRequestID: authRequestID.value } : {}) } })
}
</script>

<template>
  <KestonIdPage :brand="client ? 'tkg' : 'kestonId'">
    <div v-if="!accounts" class="flex justify-center py-12"><Spinner label="Loading" /></div>
    <Card v-else>
      <div class="flex flex-col gap-6">
        <div class="flex flex-col gap-1 text-center">
          <h1 tabindex="-1" class="text-xl font-bold outline-none">Choose an account</h1>
          <p v-if="client" class="flex flex-wrap items-center justify-center gap-1 text-base">
            to continue to <AppName :client="client" as="h2" heading-class="text-base font-bold" />
          </p>
          <p v-else class="text-base">Signed in to this browser</p>
        </div>

        <ul class="flex flex-col divide-y divide-black/10 rounded border border-black/15" aria-label="Signed-in accounts">
          <li v-for="account in accounts" :key="account.id">
            <button
              type="button"
              class="flex w-full cursor-pointer items-center gap-3 px-3 py-3 text-left outline-2 -outline-offset-2 outline-transparent transition-colors hover:bg-surface-elevated focus-visible:outline-focus disabled:cursor-wait"
              :disabled="!!choosing"
              @click="choose(account)"
            >
              <Avatar :user="{ name: account.name }" size="md" decorative />
              <span class="flex min-w-0 flex-1 flex-col">
                <span class="flex items-center gap-2">
                  <span class="truncate text-sm font-bold">{{ account.name }}</span>
                  <Badge v-if="account.active && !client" size="sm" color="green">Using now</Badge>
                </span>
                <span class="truncate text-xs text-black/65">{{ account.email }}</span>
                <span v-if="account.needsMfa" class="text-xs text-black/65">Needs a code to finish signing in</span>
              </span>
              <Spinner v-if="choosing === account.id" size="sm" label="Switching" />
              <ChevronRight v-else class="size-4 shrink-0 text-black/55" aria-hidden="true" />
            </button>
          </li>
        </ul>

        <p v-if="error" class="text-sm text-red" role="alert">{{ error }}</p>

        <div class="flex flex-col gap-2">
          <Button @click="useAnother">
            <template #leading><UserPlus /></template>
            Use a different account
          </Button>
          <Divider />
          <Button variant="ghost" @click="signOut(router, true)">
            <template #leading><LogOut /></template>
            Sign out of all accounts
          </Button>
        </div>
      </div>
    </Card>
  </KestonIdPage>
</template>

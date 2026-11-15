<script setup lang="ts">
import { KeyRound, Plus } from '@lucide/vue'
import { Badge, Button, Card, EmptyState, Spinner, formatDate } from '@thekestongroup/ui'
import { onMounted, ref } from 'vue'
import { api, type Passkey } from '../lib/api'
import { passkeysSupported } from '../lib/passkeys'
import AddPasskeySlideover from './AddPasskeySlideover.vue'
import EditPasskeySlideover from './EditPasskeySlideover.vue'

/**
 * The account's passkeys and security keys: each with its name and when it
 * was last used, to add, rename and remove. They count as MFA, and passkeys
 * also sign in without a password.
 */
const passkeys = ref<Passkey[]>()
const adding = ref(false)
const editing = ref(false)
const chosen = ref<Passkey>()
const supported = passkeysSupported()

async function load() {
  passkeys.value = await api.passkeys()
}
onMounted(load)

function edit(p: Passkey) {
  chosen.value = p
  editing.value = true
}
</script>

<template>
  <Card
    as="section"
    title="Passkeys and security keys"
    description="Sign in with your fingerprint, face or screen lock instead of a password. They also count as MFA."
  >
    <template v-if="supported && passkeys?.length" #actions>
      <Button size="sm" @click="adding = true">
        <template #leading><Plus /></template>
        Add
      </Button>
    </template>
    <div v-if="!passkeys" class="flex justify-center py-4"><Spinner label="Loading" /></div>
    <EmptyState
      v-else-if="!passkeys.length"
      :icon="KeyRound"
      size="sm"
      :heading-level="3"
      title="No passkeys yet"
      :description="supported ? 'Add one to sign in faster, without your password.' : 'This browser can\'t use passkeys.'"
    >
      <template v-if="supported" #actions>
        <Button size="sm" variant="primary" @click="adding = true">Add a passkey</Button>
      </template>
    </EmptyState>
    <ul v-else class="flex flex-col divide-y divide-black/10">
      <li v-for="p in passkeys" :key="p.id" class="flex items-center gap-3 py-3 first:pt-0 last:pb-0">
        <div class="flex min-w-0 flex-1 flex-col">
          <span class="flex min-w-0 items-center gap-2 text-sm font-bold">
            <span class="truncate">{{ p.name }}</span>
            <Badge v-if="!p.synced" size="sm">On one device</Badge>
          </span>
          <span class="text-xs text-black/65">
            <template v-if="p.lastUsedAt">Last used {{ formatDate(p.lastUsedAt) }}</template>
            <template v-else>Not used yet</template>
            · Added {{ formatDate(p.createdAt) }}
          </span>
        </div>
        <Button size="sm" @click="edit(p)">Edit<span class="sr-only"> {{ p.name }}</span></Button>
      </li>
    </ul>
  </Card>

  <AddPasskeySlideover v-model:open="adding" @added="load" />
  <EditPasskeySlideover v-model:open="editing" :passkey="chosen" @changed="load" />
</template>

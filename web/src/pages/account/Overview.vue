<script setup lang="ts">
import { Avatar, Badge, Button, Card, PageHeader, Spinner, SummaryList, formatDateTime, useNotifications } from '@thekestongroup/ui'
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { Pencil } from '@lucide/vue'
import EditProfileSlideover from '../../components/EditProfileSlideover.vue'
import GuestOrganisationsCard from '../../components/GuestOrganisationsCard.vue'
import { api, type SessionInfo } from '../../lib/api'
import { me, signOut } from '../../lib/session'

const router = useRouter()
const { notify } = useNotifications()

const user = computed(() => me.value!.user)
// What the organisation lets this person change themselves.
const editable = computed(() => me.value!.editable)
const canEdit = computed(() => editable.value.name || editable.value.email || editable.value.picture)
const profileNote = computed(() =>
  !canEdit.value
    ? 'Your organisation has restricted changing these.'
    : editable.value.name && editable.value.email && editable.value.picture
      ? undefined
      : 'Your organisation has restricted changing some of these.',
)
const editing = ref(false)
const details = computed(() => [
  { label: 'Name', value: user.value.name },
  { label: 'Email', value: user.value.email, description: 'You sign in with this.' },
  { label: 'Organisation', value: user.value.organisation },
  { label: 'Account ID', value: user.value.id, description: 'Quote this if you contact support.' },
])

// Where this account is signed in to Keston ID.
const sessions = ref<SessionInfo[]>()
const ending = ref<string>()
onMounted(async () => {
  sessions.value = await api.sessions()
})

/** A readable name for a browser, from its user agent. */
function device(ua: string) {
  const browser = /Edg\//.test(ua) ? 'Edge' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox'
    : /Safari\//.test(ua) ? 'Safari' : 'A browser'
  const os = /iPhone|iPad/.test(ua) ? 'iOS' : /Android/.test(ua) ? 'Android' : /Mac OS X/.test(ua) ? 'Mac'
    : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : ''
  return os ? `${browser} on ${os}` : browser
}

async function end(s: SessionInfo) {
  if (s.current) return signOut(router)
  ending.value = s.id
  try {
    await api.endSession(s.id)
    sessions.value = sessions.value?.filter((x) => x.id !== s.id)
    notify({ type: 'success', title: 'Signed out', description: `${device(s.userAgent)} is no longer signed in.` })
  } finally {
    ending.value = undefined
  }
}
</script>

<template>
  <PageHeader title="Your account" description="Your Keston account signs you in to every Keston app." />

  <Card title="Profile" :description="profileNote">
    <template v-if="canEdit" #actions>
      <Button size="sm" @click="editing = true">
        <template #leading><Pencil /></template>
        Edit
      </Button>
    </template>
    <div class="flex flex-col gap-4 @sm:flex-row @sm:items-start @sm:gap-6">
      <Avatar :user="user" size="xl" decorative />
      <SummaryList :items="details" class="min-w-0 flex-1" />
    </div>
  </Card>

  <EditProfileSlideover v-model:open="editing" />

  <GuestOrganisationsCard />

  <Card title="Where you're signed in" description="Sign out anywhere you don't recognise, then change your password.">
    <div v-if="!sessions" class="flex justify-center py-4"><Spinner label="Loading" /></div>
    <ul v-else class="flex flex-col divide-y divide-black/10">
      <li v-for="s in sessions" :key="s.id" class="flex items-center gap-3 py-3 first:pt-0 last:pb-0">
        <div class="flex min-w-0 flex-1 flex-col">
          <span class="flex items-center gap-2 text-sm font-bold">
            {{ device(s.userAgent) }}
            <Badge v-if="s.current" size="sm" color="green">This device</Badge>
          </span>
          <span class="text-xs text-black/65">
            Last used {{ formatDateTime(s.lastSeenAt) }}<template v-if="s.ip"> · {{ s.ip }}</template>
          </span>
        </div>
        <Button size="sm" :status="ending === s.id ? 'loading' : 'idle'" loading-text="Signing out" @click="end(s)">
          Sign out<span class="sr-only"> {{ device(s.userAgent) }}</span>
        </Button>
      </li>
    </ul>
  </Card>
</template>

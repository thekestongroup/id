<script setup lang="ts">
import { AppWindow } from '@lucide/vue'
import { Avatar, Badge, Button, Card, EmptyState, PageHeader, Spinner, formatDate, useNotifications } from '@thekestongroup/ui'
import { onMounted, ref } from 'vue'
import AppName from '../../components/AppName.vue'
import { api, type ConnectedApp } from '../../lib/api'
import { scopeIcon } from '../../lib/scopes'

/**
 * Apps on this account: Keston's own and your organisation's (marked as
 * such; optional ones can be removed), then apps you've added yourself.
 */
const { notify } = useNotifications()
const apps = ref<ConnectedApp[]>()
const removing = ref<string>()

onMounted(async () => {
  apps.value = await api.apps()
})

async function remove(app: ConnectedApp) {
  removing.value = app.client.id
  try {
    await api.revokeApp(app.client.id)
    apps.value = apps.value?.filter((a) => a.client.id !== app.client.id)
    notify({
      type: 'success',
      title: 'Access removed',
      description: `${app.client.name} can no longer use your Keston account. It'll ask again if you sign in to it.`,
    })
  } catch (e) {
    notify({ type: 'error', title: "Couldn't remove access", description: e instanceof Error ? e.message : String(e) })
  } finally {
    removing.value = undefined
  }
}
</script>

<template>
  <PageHeader title="Connected apps" description="Apps you've signed in to with your Keston account, and what they can do." />

  <div v-if="!apps" class="flex justify-center py-12"><Spinner label="Loading apps" /></div>

  <Card v-for="app in apps" :key="app.client.id">
    <div class="flex flex-col gap-4">
      <div class="flex items-start gap-3">
        <Avatar :user="{ name: app.client.name }" size="md" decorative />
        <div class="flex min-w-0 flex-1 flex-col">
          <AppName :client="app.client" as="h2" heading-class="text-base font-bold" :center="false" />
          <span class="text-sm text-black/65">
            By {{ app.client.publisher }}<template v-if="app.grantedAt"> · connected {{ formatDate(app.grantedAt) }}</template>
          </span>
          <div v-if="app.source !== 'user'" class="mt-1">
            <Badge size="sm" color="blue">
              {{ app.source === 'forced' ? 'Enabled by your organisation' : 'Added by your organisation' }}
            </Badge>
          </div>
        </div>
      </div>
      <div v-if="app.scopes.length" class="flex flex-col gap-2">
        <h3 class="text-sm font-bold">It can:</h3>
        <ul class="flex flex-col gap-2">
          <li v-for="scope in app.scopes" :key="scope.id" class="flex items-center gap-3 text-sm">
            <component :is="scopeIcon(scope.icon)" class="size-4 shrink-0 text-black/65" aria-hidden="true" />
            {{ scope.label }}
          </li>
        </ul>
      </div>
      <p v-if="!app.scopes.length" class="text-sm text-black/65">You haven't signed in to it yet.</p>
      <div v-if="app.removable">
        <Button
          variant="danger"
          size="sm"
          :status="removing === app.client.id ? 'loading' : 'idle'"
          loading-text="Removing"
          @click="remove(app)"
        >
          Remove access<span class="sr-only"> for {{ app.client.name }}</span>
        </Button>
      </div>
    </div>
  </Card>

  <Card v-if="apps && !apps.length">
    <EmptyState
      :icon="AppWindow"
      :heading-level="2"
      title="No connected apps"
      description="When you sign in to an app with your Keston account, it'll show here and you can remove its access."
    />
  </Card>
</template>

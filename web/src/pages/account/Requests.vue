<script setup lang="ts">
import { AppWindow } from '@lucide/vue'
import { Avatar, Badge, Button, Card, EmptyState, PageHeader, Spinner, formatDate, useNotifications } from '@thekestongroup/ui'
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import RequestAccessForm from '../../components/RequestAccessForm.vue'
import { api, type AppRequest, type ClientView } from '../../lib/api'

/**
 * Apps your organisation has that you can't use yet (ask for one, with a
 * reason), and how your earlier requests went.
 */
const { t } = useI18n()
const { notify } = useNotifications()
const requests = ref<AppRequest[]>()
const apps = ref<ClientView[]>()
const asking = ref<string>()
const withdrawing = ref<string>()

async function load() {
  ;[requests.value, apps.value] = await Promise.all([api.appRequests(), api.requestableApps()])
  // They're looking at the outcomes now.
  if (requests.value.some((r) => r.status !== 'pending' && !r.seen)) api.appRequestsSeen().catch(() => {})
}
onMounted(load)

const pendingFor = (id: string) => requests.value?.some((r) => r.clientId === id && r.status === 'pending') ?? false
const color = (s: AppRequest['status']) => (s === 'approved' ? 'green' : s === 'declined' ? 'red' : 'blue')

async function sent() {
  asking.value = undefined
  await load()
}

async function withdraw(r: AppRequest) {
  withdrawing.value = r.id
  try {
    await api.cancelAppRequest(r.id)
    notify({ type: 'success', title: t('appRequests.withdrawn') })
    await load()
  } catch (e) {
    notify({ type: 'error', title: t('appRequests.couldntWithdraw'), description: e instanceof Error ? e.message : String(e) })
  } finally {
    withdrawing.value = undefined
  }
}
</script>

<template>
  <PageHeader :title="t('appRequests.title')" :description="t('appRequests.description')" />
  <div v-if="!requests || !apps" class="flex justify-center py-12"><Spinner label="Loading" /></div>
  <template v-else>
    <h2 class="text-lg font-bold">{{ t('appRequests.available') }}</h2>
    <Card v-for="app in apps" :key="app.id">
      <div class="flex flex-col gap-3">
        <div class="flex items-start gap-3">
          <Avatar :user="{ name: app.name }" size="md" decorative />
          <div class="flex min-w-0 flex-1 flex-col">
            <h3 class="text-base font-bold">{{ app.name }}</h3>
            <span class="text-sm text-black/65">{{ t('appRequests.by', { publisher: app.publisher }) }}</span>
          </div>
        </div>
        <p v-if="pendingFor(app.id)" class="text-sm text-black/65">{{ t('appRequests.pendingHint') }}</p>
        <RequestAccessForm
          v-else-if="asking === app.id"
          :client-id="app.id"
          :client-name="app.name"
          @sent="sent"
          @cancel="asking = undefined"
        />
        <div v-else>
          <Button size="sm" @click="asking = app.id">
            {{ t('appRequests.request') }}<span class="sr-only"> {{ app.name }}</span>
          </Button>
        </div>
      </div>
    </Card>
    <Card v-if="!apps.length">
      <EmptyState :icon="AppWindow" :heading-level="3" :title="t('appRequests.noneAvailable')" description="" />
    </Card>

    <h2 class="mt-2 text-lg font-bold">{{ t('appRequests.yourRequests') }}</h2>
    <Card v-for="r in requests" :key="r.id">
      <div class="flex flex-col gap-2">
        <div class="flex flex-wrap items-center gap-2">
          <h3 class="text-base font-bold">{{ r.appName }}</h3>
          <Badge size="sm" :color="color(r.status)">{{ t(`appRequests.status.${r.status}`) }}</Badge>
        </div>
        <span class="text-sm text-black/65">{{ t('appRequests.asked', { date: formatDate(r.createdAt) }) }}</span>
        <p class="text-sm">{{ t('appRequests.yourReason', { reason: r.reason }) }}</p>
        <p v-if="r.decidedAt && r.status !== 'cancelled'" class="text-sm text-black/65">
          {{ t('appRequests.decided', { status: t(`appRequests.status.${r.status}`), date: formatDate(r.decidedAt), name: r.decidedByName }) }}
        </p>
        <p v-if="r.decisionMessage" class="text-sm">
          {{ t('appRequests.theirMessage', { name: r.decidedByName, message: r.decisionMessage }) }}
        </p>
        <div v-if="r.status === 'pending'">
          <Button
            variant="basic"
            size="sm"
            :status="withdrawing === r.id ? 'loading' : 'idle'"
            :loading-text="t('appRequests.withdrawing')"
            @click="withdraw(r)"
          >
            {{ t('appRequests.withdraw') }}<span class="sr-only"> {{ r.appName }}</span>
          </Button>
        </div>
      </div>
    </Card>
    <Card v-if="!requests.length"><p class="text-sm text-black/65">{{ t('appRequests.noRequests') }}</p></Card>
  </template>
</template>

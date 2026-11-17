<script setup lang="ts">
import { AppWindow, House, ShieldCheck } from '@lucide/vue'
import {
  AppShell,
  NotificationPane,
  createNotifications,
  type Notifications,
  type SidebarSection,
} from '@thekestongroup/ui'
import { computed, onMounted, onUnmounted, shallowRef, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router'
import GuestInvitationPopup from '../../components/GuestInvitationPopup.vue'
import { api, type Notification } from '../../lib/api'
import { invitations, loadInvitations } from '../../lib/guests'
import { me, signOut } from '../../lib/session'

const { t } = useI18n()

/**
 * Every account page, laid out like Keston UI's "Examples/App pages": the
 * Keston header, the sidebar, and the page in a column.
 */
const route = useRoute()
const router = useRouter()

// ── Notifications and the one-time guest invitation pop-up ──────────────────

const notifications = shallowRef<Notifications>(createNotifications())
const showInvitations = ref(false)
let lastIds = ''
function toInput(n: Notification) {
  return {
    id: n.id,
    type: n.type,
    title: n.title,
    description: n.body,
    createdAt: new Date(n.createdAt),
    read: !!n.readAt,
    // An invitation is answered in the pop-up.
    action: n.link === '/invitations' ? { label: t('guests.notifications.open'), onSelect: () => (showInvitations.value = true) } : undefined,
  }
}
async function loadNotifications() {
  const list = await api.notifications().catch(() => undefined)
  if (!list) return
  const ids = list.map((n) => n.id + (n.readAt ? 'r' : '')).join()
  if (ids === lastIds) return
  lastIds = ids
  notifications.value = createNotifications(list.map(toInput))
}
watch(
  () => notifications.value.paneOpen,
  (open) => {
    if (open && notifications.value.unreadCount.value > 0) api.readNotifications().catch(() => {})
  },
)
watch(
  () => notifications.value.items.length,
  (n, before) => {
    if (n === 0 && before > 0) api.clearNotifications().then(() => (lastIds = '')).catch(() => {})
  },
)
async function refresh() {
  await Promise.all([loadNotifications(), loadInvitations()])
}
let timer: ReturnType<typeof setInterval> | undefined
onMounted(() => {
  refresh()
  timer = setInterval(refresh, 60_000)
})
onUnmounted(() => clearInterval(timer))

const nav = computed<SidebarSection[]>(() => [
  {
    label: 'Account',
    items: [
      { label: 'Overview', icon: House, to: '/account' },
      { label: 'Security', icon: ShieldCheck, to: '/account/security' },
      { label: 'Connected apps', icon: AppWindow, to: '/account/apps' },
    ].map((item) => ({ ...item, active: route.path === item.to })),
  },
])
</script>

<template>
  <AppShell
    v-if="me"
    title="Keston ID"
    title-to="/account"
    :sections="nav"
    :user="me.user"
    :link-component="RouterLink"
    @account-settings="router.push('/account')"
    @switch-account="router.push('/choose-account')"
    @log-out="signOut(router)"
  >
    <template #header-trailing>
      <NotificationPane :notifications="notifications" />
    </template>
    <div class="flex max-w-3xl flex-col gap-6 p-4 sm:p-6">
      <RouterView />
    </div>
    <GuestInvitationPopup v-model:show="showInvitations" :invitations="invitations" @answered="refresh" />
  </AppShell>
</template>

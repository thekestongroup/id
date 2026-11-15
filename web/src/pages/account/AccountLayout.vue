<script setup lang="ts">
import { AppWindow, House, ShieldCheck } from '@lucide/vue'
import { AppShell, type SidebarSection } from '@thekestongroup/ui'
import { computed } from 'vue'
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router'
import { me, signOut } from '../../lib/session'

/**
 * Every account page, laid out like Keston UI's "Examples/App pages": the
 * Keston header, the sidebar, and the page in a column.
 */
const route = useRoute()
const router = useRouter()

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
    <div class="flex max-w-3xl flex-col gap-6 p-4 sm:p-6">
      <RouterView />
    </div>
  </AppShell>
</template>

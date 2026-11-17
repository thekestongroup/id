<script setup lang="ts">
import { Building2 } from '@lucide/vue'
import { Badge, Button, type ButtonStatus, Card, Slideover, useNotifications } from '@thekestongroup/ui'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { api, type Guest } from '../lib/api'
import { invitations, loadInvitations } from '../lib/guests'
import { me } from '../lib/session'

const { t } = useI18n()

/**
 * Your organisations: your home one, the ones you're a guest in (with
 * Leave), and invitations waiting for an answer.
 */
const { notify } = useNotifications()

const guestIn = ref<Guest[]>([])
async function load() {
  guestIn.value = await api.guestMemberships().catch(() => [])
}
onMounted(load)

const home = computed(() => me.value?.user.organisation ?? '')

const leaving = ref<Guest>()
const leavingOpen = computed({ get: () => !!leaving.value, set: (v) => !v && (leaving.value = undefined) })
const status = ref<ButtonStatus>('idle')
async function leave() {
  const g = leaving.value
  if (!g) return
  status.value = 'loading'
  try {
    await api.leaveGuest(g.id)
    notify({ type: 'success', title: t('guests.card.left', { name: g.organisationName }) })
    leaving.value = undefined
    await load()
    await loadInvitations()
  } catch (e) {
    notify({ type: 'error', title: t('guests.card.couldntLeave'), description: e instanceof Error ? e.message : String(e) })
  } finally {
    status.value = 'idle'
  }
}

const answering = ref<string>()
async function answer(g: Guest, accept: boolean) {
  answering.value = g.id
  try {
    await api.respondToInvitation(g.id, accept)
    notify({ type: 'success', title: accept ? t('guests.popup.accepted', { name: g.organisationName }) : t('guests.popup.declined') })
    await load()
    await loadInvitations()
  } catch (e) {
    notify({ type: 'error', title: t('guests.popup.couldntAnswer'), description: e instanceof Error ? e.message : String(e) })
  } finally {
    answering.value = undefined
  }
}
</script>

<template>
  <Card :title="t('guests.card.title')" :description="t('guests.card.description', { home })">
    <ul class="flex flex-col divide-y divide-black/10">
      <li class="flex items-center gap-3 py-3 first:pt-0">
        <Building2 class="size-5 shrink-0" aria-hidden="true" />
        <span class="min-w-0 flex-1 truncate font-bold">{{ home }}</span>
        <Badge size="sm" color="primary">{{ t('guests.card.home') }}</Badge>
      </li>
      <li v-for="g in guestIn" :key="g.id" class="flex items-center gap-3 py-3">
        <Building2 class="size-5 shrink-0" aria-hidden="true" />
        <span class="min-w-0 flex-1 truncate font-bold">{{ g.organisationName }}</span>
        <Badge size="sm" color="blue">{{ t('guests.card.guest') }}</Badge>
        <Button size="sm" @click="leaving = g">{{ t('guests.card.leave') }}<span class="sr-only"> {{ g.organisationName }}</span></Button>
      </li>
      <li v-if="!guestIn.length" class="py-3 text-sm text-black/65 last:pb-0">{{ t('guests.card.none') }}</li>
    </ul>

    <template v-if="invitations.length">
      <h3 class="mt-4 text-sm font-bold">{{ t('guests.card.invitations') }}</h3>
      <ul class="mt-2 flex flex-col divide-y divide-black/10">
        <li v-for="g in invitations" :key="g.id" class="flex flex-wrap items-center gap-3 py-3">
          <div class="flex min-w-0 flex-1 flex-col">
            <span class="truncate font-bold">{{ g.organisationName }}</span>
            <span class="text-xs text-black/65">{{ t('guests.card.invitedBy', { name: g.invitedByName }) }}</span>
          </div>
          <Button size="sm" :disabled="answering === g.id" @click="answer(g, false)">{{ t('guests.popup.decline') }}</Button>
          <Button size="sm" variant="primary" :disabled="answering === g.id" @click="answer(g, true)">{{ t('guests.popup.accept') }}</Button>
        </li>
      </ul>
    </template>
  </Card>

  <Slideover
    v-model:open="leavingOpen"
    :title="t('guests.card.leaveTitle', { name: leaving?.organisationName ?? '' })"
    :description="t('guests.card.leaveDescription', { name: leaving?.organisationName ?? '' })"
  >
    <template #footer="{ close }">
      <Button :disabled="status !== 'idle'" @click="close">{{ t('guests.card.cancel') }}</Button>
      <Button variant="danger" :status="status" @click="leave">{{ t('guests.card.leaveConfirm') }}</Button>
    </template>
  </Slideover>
</template>

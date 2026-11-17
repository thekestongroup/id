<script setup lang="ts">
import { Button, type ButtonStatus, Slideover, useNotifications } from '@thekestongroup/ui'
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { api, type Guest } from '../lib/api'

const { t } = useI18n()

/**
 * The one-time pop-up for a guest invitation: the first time you open your
 * account pages after it arrives (`popup`), and again from its notification
 * (`show`). Marked as seen when shown, so it doesn't come back by itself.
 */
const props = defineProps<{ invitations: (Guest & { popup: boolean })[]; show?: boolean }>()
const emit = defineEmits<{ answered: []; 'update:show': [boolean] }>()
const { notify } = useNotifications()

const open = ref(false)
const status = ref<ButtonStatus>('idle')
const item = computed(() => props.invitations[0])

watch(
  [() => props.invitations, () => props.show],
  () => {
    if (open.value) return
    if (props.show ? props.invitations.length : props.invitations.some((i) => i.popup)) open.value = true
  },
  { immediate: true },
)
watch(
  [open, item],
  () => {
    const i = item.value
    if (open.value && i?.popup) {
      api.promptSeen(i.id).catch(() => {})
      i.popup = false
    }
  },
  { immediate: true },
)
watch(open, (o) => {
  if (!o) emit('update:show', false)
})

async function answer(accept: boolean) {
  const i = item.value
  if (!i) return
  status.value = 'loading'
  try {
    await api.respondToInvitation(i.id, accept)
    notify({ type: 'success', title: accept ? t('guests.popup.accepted', { name: i.organisationName }) : t('guests.popup.declined') })
    emit('answered')
    if (props.invitations.length <= 1) open.value = false
  } catch (e) {
    notify({ type: 'error', title: t('guests.popup.couldntAnswer'), description: e instanceof Error ? e.message : String(e) })
  } finally {
    status.value = 'idle'
  }
}
</script>

<template>
  <Slideover
    v-if="item"
    v-model:open="open"
    side="right"
    :title="t('guests.popup.title', { name: item.organisationName })"
    :description="t('guests.popup.description', { who: item.invitedByName, name: item.organisationName })"
  >
    <template #body>
      <p class="text-sm">{{ t('guests.popup.body', { name: item.organisationName, home: item.homeOrganisationName }) }}</p>
      <p v-if="invitations.length > 1" class="mt-4 text-xs text-black/65">{{ t('guests.popup.moreWaiting', { count: invitations.length - 1 }) }}</p>
    </template>
    <template #footer="{ close }">
      <Button :disabled="status !== 'idle'" @click="close">{{ t('guests.popup.later') }}</Button>
      <Button :disabled="status !== 'idle'" @click="answer(false)">{{ t('guests.popup.decline') }}</Button>
      <Button variant="primary" :status="status" @click="answer(true)">{{ t('guests.popup.accept') }}</Button>
    </template>
  </Slideover>
</template>

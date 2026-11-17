<script setup lang="ts">
import { Button, type ButtonStatus, InputTextArea, useNotifications } from '@thekestongroup/ui'
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { ApiError, api, type AppRequest } from '../lib/api'

/** Asks the organisation's admins for an app, with a reason (up to 500 characters). */
const props = defineProps<{ clientId: string; clientName: string }>()
const emit = defineEmits<{ sent: [request: AppRequest]; cancel: [] }>()
const { t } = useI18n()
const { notify } = useNotifications()

const MAX = 500
const reason = ref('')
const error = ref<string>()
const status = ref<ButtonStatus>('idle')

async function submit() {
  error.value = undefined
  if (!reason.value.trim()) {
    error.value = t('appRequests.reasonRequired')
    return
  }
  status.value = 'loading'
  try {
    const req = await api.requestApp(props.clientId, reason.value.trim())
    notify({ type: 'success', title: t('appRequests.sentTitle'), description: t('appRequests.sentBody') })
    emit('sent', req)
  } catch (e) {
    status.value = 'idle'
    if (e instanceof ApiError && e.field === 'reason') error.value = e.message
    else notify({ type: 'error', title: t('appRequests.couldntSend'), description: e instanceof Error ? e.message : String(e) })
  }
}
</script>

<template>
  <form class="flex flex-col gap-3" novalidate :aria-label="t('appRequests.requestFor', { app: clientName })" @submit.prevent="submit">
    <InputTextArea
      v-model="reason"
      :label="t('appRequests.reasonLabel')"
      :helper="t('appRequests.reasonHelper', { max: MAX })"
      :error-text="error"
      :maxlength="MAX"
    />
    <div class="flex gap-2">
      <Button type="submit" size="sm" :status="status" :loading-text="t('appRequests.sending')">{{ t('appRequests.send') }}</Button>
      <Button type="button" size="sm" variant="basic" @click="emit('cancel')">{{ t('appRequests.cancel') }}</Button>
    </div>
  </form>
</template>

<script setup lang="ts">
import { Button, type ButtonStatus, InputPassword, Slideover, useNotifications } from '@thekestongroup/ui'
import { ref, watch } from 'vue'
import { api } from '../lib/api'
import { loadMe } from '../lib/session'

/**
 * Turning off MFA, which needs the password. With passkeys, it's only the
 * authenticator app that goes: MFA stays on with them.
 */
const open = defineModel<boolean>('open', { default: false })
const props = defineProps<{ passkeys?: number }>()
const { notify } = useNotifications()

const password = ref('')
const error = ref<string>()
const status = ref<ButtonStatus>('idle')

watch(open, (isOpen) => {
  if (!isOpen) return
  password.value = ''
  error.value = undefined
  status.value = 'idle'
})

async function turnOff() {
  error.value = password.value ? undefined : 'Enter your password'
  if (error.value) return
  status.value = 'loading'
  try {
    await api.mfaDisable(password.value)
    await loadMe(true)
    open.value = false
    notify(props.passkeys
      ? { title: 'Authenticator app removed', description: 'You use your passkeys after your password now.' }
      : { title: 'MFA is off', description: 'Only your password is needed to sign in now.' })
  } catch (e) {
    status.value = 'idle'
    error.value = e instanceof Error ? e.message : String(e)
  }
}
</script>

<template>
  <Slideover
    v-model:open="open"
    :title="passkeys ? 'Turn off your authenticator app' : 'Turn off MFA'"
    :description="
      passkeys
        ? 'You\'ll still use your passkeys after your password. Your backup codes will stop working.'
        : 'Anyone with your password could then sign in as you. Your backup codes will stop working.'
    "
    initial-focus="auto"
  >
    <template #body>
      <form class="flex flex-col gap-4" novalidate @submit.prevent="turnOff">
        <InputPassword v-model="password" label="Your password" autocomplete="current-password" :error-text="error" />
        <button type="submit" class="hidden" tabindex="-1" aria-hidden="true" />
      </form>
    </template>
    <template #footer="{ close }">
      <Button :disabled="status !== 'idle'" @click="close">Cancel</Button>
      <Button variant="danger" :status="status" loading-text="Turning off" @click="turnOff">Turn off</Button>
    </template>
  </Slideover>
</template>

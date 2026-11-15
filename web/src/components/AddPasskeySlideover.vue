<script setup lang="ts">
import { Button, type ButtonStatus, Input, InputPassword, Slideover, useNotifications } from '@thekestongroup/ui'
import { ref, watch } from 'vue'
import { ApiError, type Passkey } from '../lib/api'
import { addPasskey, cancelled, passkeyError } from '../lib/passkeys'
import { loadMe } from '../lib/session'

/**
 * Adding a passkey or security key: a name for it, then the browser's own
 * dialog. Without a recent sign-in, the server asks for the password first.
 */
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ added: [passkey: Passkey] }>()
const { notify } = useNotifications()

const name = ref('')
const password = ref('')
const needsPassword = ref(false)
const errors = ref<{ name?: string; password?: string; form?: string }>({})
const status = ref<ButtonStatus>('idle')

watch(open, (isOpen) => {
  if (!isOpen) return
  name.value = password.value = ''
  needsPassword.value = false
  errors.value = {}
  status.value = 'idle'
})

async function add() {
  errors.value = {
    name: name.value.trim() ? undefined : 'Enter a name',
    password: needsPassword.value && !password.value ? 'Enter your password' : undefined,
  }
  if (errors.value.name || errors.value.password) return
  status.value = 'loading'
  try {
    const passkey = await addPasskey(name.value.trim(), needsPassword.value ? password.value : undefined)
    await loadMe(true)
    emit('added', passkey)
    open.value = false
    notify({ type: 'success', title: 'Passkey added', description: `You can use ${passkey.name} to sign in now.` })
  } catch (e) {
    status.value = 'idle'
    if (cancelled(e)) return
    if (e instanceof ApiError && e.code === 'reauthenticate') {
      needsPassword.value = true
      errors.value = { password: e.message }
    } else if (e instanceof ApiError && (e.field === 'name' || e.field === 'password')) {
      errors.value = { [e.field]: e.message }
    } else {
      errors.value = { form: passkeyError(e) }
    }
  }
}
</script>

<template>
  <Slideover
    v-model:open="open"
    title="Add a passkey"
    description="Sign in with your fingerprint, face or screen lock, or with a security key, instead of a password. Your browser or password manager will ask you to make one."
    initial-focus="auto"
  >
    <template #body>
      <form class="flex flex-col gap-4" novalidate @submit.prevent="add">
        <Input
          v-model="name"
          label="Name"
          helper="So you can tell your passkeys apart, like “MacBook” or “YubiKey”."
          :max-length="64"
          :error-text="errors.name"
        />
        <InputPassword
          v-if="needsPassword"
          v-model="password"
          label="Your password"
          helper="You signed in a while ago, so confirm it's you."
          autocomplete="current-password"
          :error-text="errors.password"
        />
        <p v-if="errors.form" class="text-sm text-red" role="alert">{{ errors.form }}</p>
        <button type="submit" class="hidden" tabindex="-1" aria-hidden="true" />
      </form>
    </template>
    <template #footer="{ close }">
      <Button :disabled="status !== 'idle'" @click="close">Cancel</Button>
      <Button variant="primary" :status="status" loading-text="Waiting for your passkey" @click="add">Add passkey</Button>
    </template>
  </Slideover>
</template>

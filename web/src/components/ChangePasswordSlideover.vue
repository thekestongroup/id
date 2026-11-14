<script setup lang="ts">
import { Button, type ButtonStatus, InputPassword, Slideover, useNotifications } from '@thekestongroup/ui'
import { reactive, ref, watch } from 'vue'
import { api, ApiError } from '../lib/api'
import { loadMe } from '../lib/session'

/** Changing the password, in a Slideover. Signs out every other device. */
const open = defineModel<boolean>('open', { default: false })
const { notify } = useNotifications()

const form = reactive({ current: '', next: '', confirm: '' })
const errors = reactive<{ current?: string; next?: string; confirm?: string }>({})
const status = ref<ButtonStatus>('idle')

// Start clean each time it opens.
watch(open, (isOpen) => {
  if (!isOpen) return
  Object.assign(form, { current: '', next: '', confirm: '' })
  Object.assign(errors, { current: undefined, next: undefined, confirm: undefined })
  status.value = 'idle'
})

async function save() {
  errors.current = form.current ? undefined : 'Enter your current password'
  errors.next = form.next.length >= 12 ? undefined : 'Use at least 12 characters'
  errors.confirm = form.confirm === form.next ? undefined : "The passwords don't match"
  if (errors.current || errors.next || errors.confirm) return
  status.value = 'loading'
  try {
    await api.changePassword(form.current, form.next)
    await loadMe(true)
    open.value = false
    notify({ type: 'success', title: 'Password changed', description: "You've been signed out everywhere else." })
  } catch (e) {
    status.value = 'idle'
    if (e instanceof ApiError && e.field === 'current') errors.current = e.message
    else if (e instanceof ApiError && e.field === 'new') errors.next = e.message
    else notify({ type: 'error', title: "Couldn't change your password", description: e instanceof Error ? e.message : String(e) })
  }
}
</script>

<template>
  <Slideover
    v-model:open="open"
    title="Change your password"
    description="You'll stay signed in here. Everywhere else, you'll need the new password."
    initial-focus="auto"
  >
    <template #body>
      <form id="change-password" class="flex flex-col gap-4" novalidate @submit.prevent="save">
        <InputPassword v-model="form.current" label="Current password" autocomplete="current-password" :error-text="errors.current" />
        <InputPassword
          v-model="form.next"
          label="New password"
          helper="At least 12 characters. A few random words works well."
          autocomplete="new-password"
          :error-text="errors.next"
        />
        <InputPassword v-model="form.confirm" label="New password again" autocomplete="new-password" :error-text="errors.confirm" />
        <!-- Enter in a field submits. -->
        <button type="submit" class="hidden" tabindex="-1" aria-hidden="true" />
      </form>
    </template>
    <template #footer="{ close }">
      <Button :disabled="status !== 'idle'" @click="close">Cancel</Button>
      <Button variant="primary" :status="status" loading-text="Saving" @click="save">Save password</Button>
    </template>
  </Slideover>
</template>

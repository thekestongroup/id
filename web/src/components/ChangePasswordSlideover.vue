<script setup lang="ts">
import { Button, type ButtonStatus, InputPassword, Slideover, useNotifications } from '@thekestongroup/ui'
import { computed, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import PasswordRules from './PasswordRules.vue'
import { api, ApiError } from '../lib/api'
import { ruleMet } from '../lib/passwordRules'
import { loadMe, me } from '../lib/session'

/** Changing the password, in a Slideover. Signs out every other device. */
const open = defineModel<boolean>('open', { default: false })
const { notify } = useNotifications()
const { t } = useI18n()
const rules = computed(() => me.value?.security.passwordRules ?? [])
/** After a try that didn't meet the rules: unmet ones turn red. */
const tried = ref(false)

const form = reactive({ current: '', next: '', confirm: '' })
const errors = reactive<{ current?: string; next?: string; confirm?: string }>({})
const status = ref<ButtonStatus>('idle')

// Start clean each time it opens.
watch(open, (isOpen) => {
  if (!isOpen) return
  Object.assign(form, { current: '', next: '', confirm: '' })
  Object.assign(errors, { current: undefined, next: undefined, confirm: undefined })
  status.value = 'idle'
  tried.value = false
})

async function save() {
  errors.current = form.current ? undefined : 'Enter your current password'
  errors.next = undefined
  errors.confirm = form.confirm === form.next ? undefined : t('changePassword.mismatch')
  const met = rules.value.every((r) => ruleMet(r, form.next))
  tried.value = !met
  if (errors.current || !met || errors.confirm) return
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
          :label="t('changePassword.newLabel')"
          autocomplete="new-password"
          :error-text="errors.next"
        />
        <PasswordRules :rules="rules" :password="form.next" :invalid="tried" />
        <InputPassword v-model="form.confirm" :label="t('changePassword.confirmLabel')" autocomplete="new-password" :error-text="errors.confirm" />
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

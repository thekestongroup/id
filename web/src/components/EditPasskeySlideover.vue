<script setup lang="ts">
import { Button, type ButtonStatus, Input, Slideover, useNotifications } from '@thekestongroup/ui'
import { ref, watch } from 'vue'
import { api, ApiError, type Passkey } from '../lib/api'
import { loadMe } from '../lib/session'

/** Renaming or removing one passkey or security key. */
const open = defineModel<boolean>('open', { default: false })
const props = defineProps<{ passkey?: Passkey }>()
const emit = defineEmits<{ changed: [] }>()
const { notify } = useNotifications()

const name = ref('')
const error = ref<string>()
const saving = ref<ButtonStatus>('idle')
const removing = ref<ButtonStatus>('idle')

watch(open, (isOpen) => {
  if (!isOpen) return
  name.value = props.passkey?.name ?? ''
  error.value = undefined
  saving.value = removing.value = 'idle'
})

const fail = (title: string, e: unknown) =>
  notify({ type: 'error', title, description: e instanceof Error ? e.message : String(e) })

async function save() {
  error.value = name.value.trim() ? undefined : 'Enter a name'
  if (error.value || !props.passkey) return
  saving.value = 'loading'
  try {
    await api.renamePasskey(props.passkey.id, name.value.trim())
    emit('changed')
    open.value = false
  } catch (e) {
    saving.value = 'idle'
    if (e instanceof ApiError && e.field === 'name') error.value = e.message
    else fail("Couldn't rename it", e)
  }
}

async function remove() {
  if (!props.passkey) return
  removing.value = 'loading'
  try {
    await api.removePasskey(props.passkey.id)
    await loadMe(true)
    emit('changed')
    open.value = false
    notify({ title: 'Passkey removed', description: `${props.passkey.name} can't be used to sign in any more.` })
  } catch (e) {
    removing.value = 'idle'
    fail("Couldn't remove it", e)
  }
}
</script>

<template>
  <Slideover
    v-model:open="open"
    title="Edit passkey"
    description="Remove it if you've lost the device or security key, or don't use it any more."
    initial-focus="auto"
  >
    <template #body>
      <form class="flex flex-col gap-4" novalidate @submit.prevent="save">
        <Input v-model="name" label="Name" :max-length="64" :error-text="error" />
        <button type="submit" class="hidden" tabindex="-1" aria-hidden="true" />
      </form>
    </template>
    <template #footer="{ close }">
      <Button variant="danger" :status="removing" :disabled="saving !== 'idle'" loading-text="Removing" @click="remove">
        Remove
      </Button>
      <Button :disabled="saving !== 'idle' || removing !== 'idle'" @click="close">Cancel</Button>
      <Button variant="primary" :status="saving" :disabled="removing !== 'idle'" loading-text="Saving" @click="save">
        Save
      </Button>
    </template>
  </Slideover>
</template>

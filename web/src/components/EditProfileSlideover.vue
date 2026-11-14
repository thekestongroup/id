<script setup lang="ts">
import { ImageUp, Trash2 } from '@lucide/vue'
import { Avatar, Button, type ButtonStatus, Input, Slideover, useNotifications } from '@thekestongroup/ui'
import { reactive, ref, watch } from 'vue'
import { ApiError, api } from '../lib/api'
import { loadMe, me } from '../lib/session'

/**
 * Editing your own profile: only the fields your organisation lets you
 * change (name, email, profile picture). The rest aren't shown here.
 */
const open = defineModel<boolean>('open', { default: false })
const { notify } = useNotifications()

const form = reactive({ name: '', username: '' })
const errors = reactive<{ name?: string; username?: string; picture?: string }>({})
const status = ref<ButtonStatus>('idle')
const pictureBusy = ref(false)
const fileInput = ref<HTMLInputElement>()

watch(open, (isOpen) => {
  if (!isOpen || !me.value) return
  form.name = me.value.user.name
  form.username = me.value.username
  Object.assign(errors, { name: undefined, username: undefined, picture: undefined })
  status.value = 'idle'
})

const message = (e: unknown) => (e instanceof Error ? e.message : String(e))

async function save() {
  const m = me.value!
  const changes: { name?: string; username?: string } = {}
  if (m.editable.name && form.name.trim() !== m.user.name) changes.name = form.name.trim()
  if (m.editable.email && form.username.trim().toLowerCase() !== m.username) changes.username = form.username
  if (!Object.keys(changes).length) {
    open.value = false
    return
  }
  status.value = 'loading'
  Object.assign(errors, { name: undefined, username: undefined })
  try {
    await api.updateProfile(changes)
    await loadMe(true)
    open.value = false
    notify({ type: 'success', title: 'Profile updated' })
  } catch (e) {
    status.value = 'idle'
    if (e instanceof ApiError && (e.field === 'name' || e.field === 'username')) errors[e.field] = e.message
    else notify({ type: 'error', title: 'Couldn’t update your profile', description: message(e) })
  }
}

async function upload(event: Event) {
  const file = (event.target as HTMLInputElement).files?.[0]
  if (!file) return
  pictureBusy.value = true
  errors.picture = undefined
  try {
    await api.setPicture(file)
    await loadMe(true)
  } catch (e) {
    errors.picture = message(e)
  } finally {
    pictureBusy.value = false
    if (fileInput.value) fileInput.value.value = ''
  }
}

async function removePicture() {
  pictureBusy.value = true
  try {
    await api.removePicture()
    await loadMe(true)
  } catch (e) {
    errors.picture = message(e)
  } finally {
    pictureBusy.value = false
  }
}
</script>

<template>
  <Slideover v-model:open="open" title="Edit your profile" initial-focus="auto">
    <template #body>
      <form v-if="me" class="flex flex-col gap-6" novalidate @submit.prevent="save">
        <div v-if="me.editable.picture" class="flex flex-col gap-3">
          <p class="text-sm font-bold">Profile picture</p>
          <div class="flex items-center gap-4">
            <Avatar :user="me.user" size="xl" decorative />
            <div class="flex flex-wrap gap-2">
              <Button size="sm" :status="pictureBusy ? 'loading' : 'idle'" loading-text="Uploading" @click="fileInput?.click()">
                <template #leading><ImageUp /></template>
                {{ me.user.avatar ? 'Change picture' : 'Add a picture' }}
              </Button>
              <Button v-if="me.user.avatar" size="sm" variant="ghost" :disabled="pictureBusy" @click="removePicture">
                <template #leading><Trash2 /></template>
                Remove
              </Button>
            </div>
            <input ref="fileInput" type="file" accept="image/png,image/jpeg,image/gif" class="sr-only" tabindex="-1" aria-hidden="true" @change="upload" />
          </div>
          <p v-if="errors.picture" class="text-sm text-red" role="alert">{{ errors.picture }}</p>
          <p v-else class="text-xs text-black/65">PNG, JPEG or GIF, under 2 MB. Square pictures look best.</p>
        </div>

        <Input v-if="me.editable.name" v-model="form.name" label="Name" autocomplete="name" :error-text="errors.name" />
        <Input
          v-if="me.editable.email"
          v-model="form.username"
          label="Email"
          autocapitalize="off"
          spellcheck="false"
          helper="You sign in with this. Your apps may need you to sign in again."
          :error-text="errors.username"
        >
          <template #trailing><span class="text-sm text-black/65">@{{ me.domain }}</span></template>
        </Input>
        <button type="submit" class="hidden" tabindex="-1" aria-hidden="true" />
      </form>
    </template>
    <template #footer="{ close }">
      <Button :disabled="status !== 'idle'" @click="close">{{ me?.editable.name || me?.editable.email ? 'Cancel' : 'Done' }}</Button>
      <Button v-if="me?.editable.name || me?.editable.email" variant="primary" :status="status" loading-text="Saving" @click="save">
        Save
      </Button>
    </template>
  </Slideover>
</template>

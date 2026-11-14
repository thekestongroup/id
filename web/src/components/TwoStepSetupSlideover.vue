<script setup lang="ts">
import { InputCode, type InputCodeProps, Link, Slideover, Spinner, useNotifications } from '@thekestongroup/ui'
import { computed, ref, watch } from 'vue'
import { api } from '../lib/api'
import { loadMe } from '../lib/session'

/**
 * Turning on two-step verification, as a multi-step Slideover:
 * 1. Add Keston ID to an authenticator app: scan the QR code, or open it in
 *    the app (on a phone), or type the setup key.
 * 2. Enter the code the app shows, which turns it on.
 * 3. Save the backup codes (shown once).
 * Then a success notification.
 */
const open = defineModel<boolean>('open', { default: false })
const { notify } = useNotifications()

const steps = ['Add Keston ID to your app', 'Enter the code', 'Save your backup codes']
const step = ref(0)
const setup = ref<{ secret: string; otpauthUrl: string; qrCode: string }>()
const setupError = ref<string>()
const showKey = ref(false)

const code = ref('')
const codeStatus = ref<InputCodeProps['status']>()
const codeText = ref<string>()
const backupCodes = ref<string[]>()
/** Turned on in this run and not yet announced. Kept apart from backupCodes,
 *  so the codes stay on screen while the panel slides away. */
const turnedOn = ref(false)

const keyGroups = computed(() => setup.value?.secret.match(/.{1,4}/g)?.join(' ') ?? '')
const message = (e: unknown) => (e instanceof Error ? e.message : String(e))

// Each time it opens: start again with a new secret.
watch(open, async (isOpen) => {
  if (!isOpen) return finished()
  step.value = 0
  setup.value = setupError.value = backupCodes.value = undefined
  code.value = ''
  codeStatus.value = codeText.value = undefined
  showKey.value = false
  try {
    setup.value = await api.twoStepSetup()
  } catch (e) {
    setupError.value = message(e)
  }
})

/** Turns it on with the code. Returns whether that worked. */
async function enable(): Promise<boolean> {
  if (backupCodes.value) return true // already on (came back with Previous)
  if (code.value.length < 6) {
    codeStatus.value = 'error'
    codeText.value = 'Enter all 6 digits'
    return false
  }
  codeStatus.value = 'loading'
  codeText.value = 'Checking code…'
  try {
    backupCodes.value = (await api.twoStepEnable(code.value)).backupCodes
    turnedOn.value = true
    codeStatus.value = 'success'
    codeText.value = 'Code accepted'
    return true
  } catch (e) {
    codeStatus.value = 'error'
    codeText.value = message(e)
    code.value = ''
    return false
  }
}

async function validateStep(current: number) {
  if (current === 0) return !!setup.value
  if (current === 1) return enable()
  return true
}

// All six digits typed: check them and move on, without pressing Next.
async function onComplete() {
  if (await enable()) step.value = 2
}

// Once it's on, closing (Done, ×, Escape) says so, and refreshes the page.
async function finished() {
  if (!turnedOn.value) return
  turnedOn.value = false
  await loadMe(true)
  notify({
    type: 'success',
    title: 'Two-step verification is on',
    description: "Next time you sign in, we'll ask for a code from your authenticator app.",
  })
}
</script>

<template>
  <Slideover
    v-model:open="open"
    v-model:step="step"
    title="Turn on two-step verification"
    :steps="steps"
    :validate-step="validateStep"
    finish-label="Done"
    @finish="open = false"
  >
    <template #body="{ step: current }">
      <!-- 1. Add Keston ID to the authenticator app. -->
      <div v-if="current === 0" class="flex flex-col gap-4">
        <p class="text-sm">
          Scan this QR code with an authenticator app on your phone, like Google Authenticator, Microsoft
          Authenticator or 1Password.
        </p>
        <p v-if="setupError" class="text-sm text-red" role="alert">{{ setupError }}</p>
        <div v-else-if="!setup" class="flex justify-center py-12"><Spinner label="Getting your code" /></div>
        <template v-else>
          <img
            :src="setup.qrCode"
            alt="QR code to add Keston ID to your authenticator app"
            class="mx-auto size-48 rounded border border-black/15 bg-white p-2 [image-rendering:pixelated]"
          />
          <div class="flex flex-col gap-2 text-sm">
            <p>
              On this phone? <Link :href="setup.otpauthUrl">Open in your authenticator app</Link>
            </p>
            <p v-if="!showKey">
              Can't scan it? <Link as="button" @click="showKey = true">Enter a setup key instead</Link>
            </p>
            <div v-else class="flex flex-col gap-1">
              <p>In your app, choose to enter a setup key, and type:</p>
              <p class="rounded bg-surface px-3 py-2 text-center font-mono font-bold tracking-wide break-all select-all">
                {{ keyGroups }}
              </p>
            </div>
          </div>
        </template>
      </div>

      <!-- 2. Enter the code the app shows. -->
      <div v-else-if="current === 1" class="flex flex-col gap-4">
        <p class="text-sm">Your authenticator app now shows a 6-digit code for Keston ID. Enter it here.</p>
        <InputCode
          v-model="code"
          label="Code from your authenticator app"
          :status="codeStatus"
          :status-text="codeText"
          :disabled="codeStatus === 'loading'"
          @complete="onComplete"
        />
      </div>

      <!-- 3. Save the backup codes. -->
      <div v-else class="flex flex-col gap-4">
        <p class="text-sm">
          If you lose your phone, each of these codes signs you in once. Save them somewhere safe, like a password
          manager. You won't see them again.
        </p>
        <ul class="grid grid-cols-2 gap-2 rounded bg-surface p-4 text-center font-mono text-sm select-all">
          <li v-for="c in backupCodes" :key="c">{{ c }}</li>
        </ul>
      </div>
    </template>
  </Slideover>
</template>

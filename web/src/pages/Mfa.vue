<script setup lang="ts">
import { Button, Card, Input, InputCode, type InputCodeProps, Link } from '@thekestongroup/ui'
import { KeyRound } from '@lucide/vue'
import { computed, nextTick, ref, watch } from 'vue'
import FlowState from '../components/FlowState.vue'
import KestonIdPage from '../components/KestonIdPage.vue'
import { api } from '../lib/api'
import { cancelled, passkeyError, passkeyMfa } from '../lib/passkeys'
import { useFlow } from '../lib/useFlow'

/**
 * MFA: a passkey or security key, a code from an authenticator app, or a
 * backup code (whichever this account has). From the TwoStepCode story in
 * Keston UI's "Examples/Keston ID".
 */
const { authRequestID, client, flow, error: flowError, loading, next } = useFlow('mfa')

type Mode = 'passkey' | 'app' | 'backup'
const mode = ref<Mode>('app')
const methods = computed(() => flow.value?.mfa ?? { app: true, passkey: false })
// With only passkeys, start there; with an app too, the code (and a link).
watch(methods, (m) => {
  if (m.passkey && !m.app) mode.value = 'passkey'
})
/** The other ways, as links under the card. */
const others = computed(() => {
  const all: { mode: Mode; label: string }[] = []
  if (methods.value.passkey) all.push({ mode: 'passkey', label: 'Use a passkey' })
  if (methods.value.app) {
    all.push({ mode: 'app', label: 'Use your authenticator app' }, { mode: 'backup', label: 'Use a backup code' })
  }
  return all.filter((o) => o.mode !== mode.value)
})

const passkeyStatus = ref<'idle' | 'loading' | 'success'>('idle')
const passkeyMessage = ref<string>()

async function usePasskey() {
  passkeyMessage.value = undefined
  passkeyStatus.value = 'loading'
  try {
    const f = await passkeyMfa(authRequestID.value)
    passkeyStatus.value = 'success'
    await next(f)
  } catch (e) {
    passkeyStatus.value = 'idle'
    if (!cancelled(e)) passkeyMessage.value = passkeyError(e)
  }
}
const code = ref('')
const status = ref<InputCodeProps['status']>()
const statusText = ref<string>()
const backup = ref('')
const backupError = ref<string>()
const checkingBackup = ref(false)

const message = (e: unknown) => (e instanceof Error ? e.message : String(e))

async function check(value = code.value) {
  if (value.length < 6) {
    status.value = 'error'
    statusText.value = 'Enter all 6 digits'
    return
  }
  status.value = 'loading'
  statusText.value = 'Checking code…'
  try {
    const flow = await api.mfa(value, 'app', authRequestID.value)
    status.value = 'success'
    statusText.value = 'Code accepted'
    await next(flow)
  } catch (e) {
    status.value = 'error'
    statusText.value = message(e)
    code.value = ''
  }
}

async function checkBackup() {
  backupError.value = backup.value.trim() ? undefined : 'Enter a backup code'
  if (backupError.value) return
  checkingBackup.value = true
  try {
    await next(await api.mfa(backup.value, 'backup', authRequestID.value))
  } catch (e) {
    backupError.value = message(e)
  } finally {
    checkingBackup.value = false
  }
}

async function switchMode(to: Mode) {
  mode.value = to
  status.value = statusText.value = backupError.value = passkeyMessage.value = undefined
  await nextTick()
  document.querySelector<HTMLElement>('main form input, main form button')?.focus()
}
</script>

<template>
  <KestonIdPage :brand="client ? 'tkg' : 'kestonId'">
    <FlowState :loading="loading" :error="flowError">
      <Card :ui="{ footer: 'justify-evenly' }">
        <div class="flex flex-col gap-4">
          <div class="flex flex-col gap-1">
            <h1 tabindex="-1" class="text-xl font-bold outline-none">Check it's you</h1>
            <p class="text-sm text-black/65">
              <template v-if="mode === 'passkey'">Use your passkey or security key to confirm it's you.</template>
              <template v-else-if="mode === 'app'">
                Open your authenticator app and enter the code for Keston ID.
              </template>
              <template v-else>Enter one of the backup codes you saved when you set up MFA.</template>
            </p>
          </div>

          <form v-if="mode === 'passkey'" class="flex flex-col gap-4" @submit.prevent="usePasskey">
            <p v-if="passkeyMessage" class="text-sm text-red" role="alert">{{ passkeyMessage }}</p>
            <Button
              type="submit"
              variant="primary"
              :status="passkeyStatus"
              loading-text="Waiting for your passkey"
              success-text="Confirmed"
            >
              <template #leading><KeyRound /></template>
              Use a passkey
            </Button>
          </form>

          <form v-else-if="mode === 'app'" class="flex flex-col gap-4" @submit.prevent="check()">
            <InputCode
              v-model="code"
              label="Code from your authenticator app"
              :status="status"
              :status-text="statusText"
              :disabled="status === 'loading'"
              class="items-center"
              @complete="check"
            />
            <Button type="submit" variant="primary" :disabled="status === 'loading'">Continue</Button>
          </form>

          <form v-else class="flex flex-col gap-4" novalidate @submit.prevent="checkBackup">
            <Input v-model="backup" label="Backup code" autocomplete="one-time-code" :error-text="backupError" />
            <Button
              type="submit"
              variant="primary"
              :status="checkingBackup ? 'loading' : 'idle'"
              loading-text="Checking"
            >
              Continue
            </Button>
          </form>
        </div>
        <template v-if="others.length" #footer>
          <Link
            v-for="o in others"
            :key="o.mode"
            as="button"
            class="py-1 text-xs text-black/65"
            @click="switchMode(o.mode)"
          >
            {{ o.label }}
          </Link>
        </template>
      </Card>
    </FlowState>
  </KestonIdPage>
</template>

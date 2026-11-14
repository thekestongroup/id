<script setup lang="ts">
import { Button, Card, Input, InputCode, type InputCodeProps, Link } from '@thekestongroup/ui'
import { nextTick, ref } from 'vue'
import FlowState from '../components/FlowState.vue'
import KestonIdPage from '../components/KestonIdPage.vue'
import { api } from '../lib/api'
import { useFlow } from '../lib/useFlow'

/**
 * The second step: a code from an authenticator app, or a backup code. From
 * the TwoStepCode story in Keston UI's "Examples/Keston ID".
 */
const { authRequestID, client, error: flowError, loading, next } = useFlow('two-step')

const mode = ref<'app' | 'backup'>('app')
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
    const flow = await api.twoStep(value, 'app', authRequestID.value)
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
    await next(await api.twoStep(backup.value, 'backup', authRequestID.value))
  } catch (e) {
    backupError.value = message(e)
  } finally {
    checkingBackup.value = false
  }
}

async function switchMode(to: 'app' | 'backup') {
  mode.value = to
  status.value = statusText.value = backupError.value = undefined
  await nextTick()
  document.querySelector<HTMLInputElement>('main form input')?.focus()
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
              <template v-if="mode === 'app'">
                Open your authenticator app and enter the code for Keston ID.
              </template>
              <template v-else>Enter one of the backup codes you saved when you set up two-step verification.</template>
            </p>
          </div>

          <form v-if="mode === 'app'" class="flex flex-col gap-4" @submit.prevent="check()">
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
        <template #footer>
          <Link v-if="mode === 'app'" as="button" class="py-1 text-xs text-black/65" @click="switchMode('backup')">
            Use a backup code
          </Link>
          <Link v-else as="button" class="py-1 text-xs text-black/65" @click="switchMode('app')">
            Use your authenticator app
          </Link>
        </template>
      </Card>
    </FlowState>
  </KestonIdPage>
</template>

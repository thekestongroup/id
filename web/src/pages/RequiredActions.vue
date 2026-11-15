<script setup lang="ts">
import {
  Button,
  type ButtonStatus,
  Card,
  InputCode,
  type InputCodeProps,
  InputPassword,
  Link,
  Spinner,
} from '@thekestongroup/ui'
import { computed, reactive, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import FlowState from '../components/FlowState.vue'
import KestonIdPage from '../components/KestonIdPage.vue'
import { api, ApiError, type Flow } from '../lib/api'
import { signOut } from '../lib/session'
import { useFlow } from '../lib/useFlow'

/**
 * Required actions, after the password (and MFA, or an access pass) and
 * before the app: choose a new password (an admin asked), then set up MFA
 * (the organisation requires it, or they signed in with an access pass).
 * One at a time; the server says what's left.
 */
const router = useRouter()
const { authRequestID, client, flow, error: flowError, loading, next } = useFlow('actions')
const action = computed(() => flow.value?.actions?.[0])
const message = (e: unknown) => (e instanceof Error ? e.message : String(e))

/** After an action: the next one here, or on to wherever the flow goes. */
async function done(f: Flow) {
  if (f.step === 'actions') flow.value = f
  else await next(f)
}

// ── Choose a new password ───────────────────────────────────────────────────

const pw = reactive({ next: '', confirm: '' })
const pwErrors = reactive<{ next?: string; confirm?: string; form?: string }>({})
const pwStatus = ref<ButtonStatus>('idle')

async function savePassword() {
  pwErrors.next = pw.next.length >= 12 ? undefined : 'Use at least 12 characters'
  pwErrors.confirm = pw.confirm === pw.next ? undefined : "The passwords don't match"
  pwErrors.form = undefined
  if (pwErrors.next || pwErrors.confirm) return
  pwStatus.value = 'loading'
  try {
    const f = await api.requiredPassword(pw.next, authRequestID.value)
    pwStatus.value = 'idle'
    await done(f)
  } catch (e) {
    pwStatus.value = 'idle'
    if (e instanceof ApiError && e.field === 'new') pwErrors.next = e.message
    else pwErrors.form = message(e)
  }
}

// ── Set up MFA ──────────────────────────────────────────────────────────────

const setup = ref<{ secret: string; otpauthUrl: string; qrCode: string }>()
const setupError = ref<string>()
const showKey = ref(false)
const code = ref('')
const codeStatus = ref<InputCodeProps['status']>()
const codeText = ref<string>()
const backupCodes = ref<string[]>()
const after = ref<Flow>()
const keyGroups = computed(() => setup.value?.secret.match(/.{1,4}/g)?.join(' ') ?? '')

watch(
  action,
  async (a) => {
    if (a !== 'mfa' || setup.value) return
    try {
      setup.value = await api.requiredMfaSetup()
    } catch (e) {
      setupError.value = message(e)
    }
  },
  { immediate: true },
)

async function enable(value = code.value) {
  if (value.length < 6) {
    codeStatus.value = 'error'
    codeText.value = 'Enter all 6 digits'
    return
  }
  codeStatus.value = 'loading'
  codeText.value = 'Checking code…'
  try {
    const res = await api.requiredMfaEnable(value, authRequestID.value)
    codeStatus.value = 'success'
    codeText.value = 'Code accepted'
    backupCodes.value = res.backupCodes
    after.value = res.flow
  } catch (e) {
    codeStatus.value = 'error'
    codeText.value = message(e)
    code.value = ''
  }
}
</script>

<template>
  <KestonIdPage :brand="client ? 'tkg' : 'kestonId'">
    <FlowState :loading="loading" :error="flowError">
      <!-- Choose a new password. -->
      <Card v-if="action === 'password'">
        <div class="flex flex-col gap-6">
          <div class="flex flex-col gap-1">
            <h1 tabindex="-1" class="text-xl font-bold outline-none">Choose a new password</h1>
            <p class="text-sm text-black/65">
              Your organisation has asked you to choose a new password before you continue.
            </p>
          </div>
          <form class="flex flex-col gap-4" novalidate @submit.prevent="savePassword">
            <InputPassword
              v-model="pw.next"
              label="New password"
              helper="At least 12 characters, different from your old one. A few random words works well."
              autocomplete="new-password"
              :error-text="pwErrors.next"
            />
            <InputPassword
              v-model="pw.confirm"
              label="New password again"
              autocomplete="new-password"
              :error-text="pwErrors.confirm"
            />
            <p v-if="pwErrors.form" class="text-sm text-red" role="alert">{{ pwErrors.form }}</p>
            <Button type="submit" variant="primary" :status="pwStatus" loading-text="Saving">Continue</Button>
          </form>
        </div>
      </Card>

      <!-- Set up MFA, then save the backup codes. -->
      <Card v-else-if="action === 'mfa'">
        <div v-if="backupCodes" class="flex flex-col gap-4">
          <div class="flex flex-col gap-1">
            <h1 tabindex="-1" class="text-xl font-bold outline-none">Save your backup codes</h1>
            <p class="text-sm text-black/65">
              MFA is on. If you lose your phone, each of these codes signs you in once. Save them somewhere safe, like
              a password manager. You won't see them again.
            </p>
          </div>
          <ul class="grid grid-cols-2 gap-2 rounded bg-surface p-4 text-center font-mono text-sm select-all">
            <li v-for="c in backupCodes" :key="c">{{ c }}</li>
          </ul>
          <Button variant="primary" @click="after && done(after)">I've saved them</Button>
        </div>
        <div v-else class="flex flex-col gap-4">
          <div class="flex flex-col gap-1">
            <h1 tabindex="-1" class="text-xl font-bold outline-none">Set up MFA</h1>
            <p class="text-sm text-black/65">
              Before you continue, add Keston ID to an authenticator app on your phone, like Google Authenticator,
              Microsoft Authenticator or 1Password. You'll enter a code from it when you sign in.
            </p>
          </div>
          <p v-if="setupError" class="text-sm text-red" role="alert">{{ setupError }}</p>
          <div v-else-if="!setup" class="flex justify-center py-12"><Spinner label="Getting your code" /></div>
          <template v-else>
            <img
              :src="setup.qrCode"
              alt="QR code to add Keston ID to your authenticator app"
              class="mx-auto size-48 rounded border border-black/15 bg-white p-2 [image-rendering:pixelated]"
            />
            <div class="flex flex-col gap-2 text-sm">
              <p>On this phone? <Link :href="setup.otpauthUrl">Open in your authenticator app</Link></p>
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
            <form class="flex flex-col gap-4" @submit.prevent="enable()">
              <InputCode
                v-model="code"
                label="Then enter the code from your authenticator app"
                :status="codeStatus"
                :status-text="codeText"
                :disabled="codeStatus === 'loading'"
                class="items-center"
                @complete="enable"
              />
              <Button type="submit" variant="primary" :disabled="codeStatus === 'loading'">Turn on MFA</Button>
            </form>
          </template>
        </div>
      </Card>

      <p class="text-center text-sm">
        <Link as="button" @click="signOut(router)">Sign out</Link>
      </p>
    </FlowState>
  </KestonIdPage>
</template>

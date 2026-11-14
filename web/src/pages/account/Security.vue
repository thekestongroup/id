<script setup lang="ts">
import { Button, type ButtonStatus, Card, InputCode, type InputCodeProps, InputPassword, Link, PageHeader, formatDate, useNotifications } from '@thekestongroup/ui'
import { computed, nextTick, reactive, ref } from 'vue'
import { api, ApiError } from '../../lib/api'
import { loadMe, me } from '../../lib/session'

const { notify } = useNotifications()
const security = computed(() => me.value!.security)
const message = (e: unknown) => (e instanceof Error ? e.message : String(e))

async function focusFirst(selector: string) {
  await nextTick()
  document.querySelector<HTMLInputElement>(`${selector} input`)?.focus()
}

// ── Password ────────────────────────────────────────────────────────────────

const changing = ref(false)
const passwords = reactive({ current: '', next: '', confirm: '' })
const pwErrors = reactive<{ current?: string; next?: string; confirm?: string }>({})
const pwStatus = ref<ButtonStatus>('idle')

function resetPassword() {
  changing.value = false
  Object.assign(passwords, { current: '', next: '', confirm: '' })
  Object.assign(pwErrors, { current: undefined, next: undefined, confirm: undefined })
}

async function savePassword() {
  pwErrors.current = passwords.current ? undefined : 'Enter your current password'
  pwErrors.next = passwords.next.length >= 12 ? undefined : 'Use at least 12 characters'
  pwErrors.confirm = passwords.confirm === passwords.next ? undefined : "The passwords don't match"
  if (pwErrors.current || pwErrors.next || pwErrors.confirm) return
  pwStatus.value = 'loading'
  try {
    await api.changePassword(passwords.current, passwords.next)
    resetPassword()
    await loadMe(true)
    notify({ type: 'success', title: 'Password changed', description: "You've been signed out everywhere else." })
  } catch (e) {
    if (e instanceof ApiError && e.field === 'current') pwErrors.current = e.message
    else if (e instanceof ApiError && e.field === 'new') pwErrors.next = e.message
    else notify({ type: 'error', title: "Couldn't change your password", description: message(e) })
  } finally {
    pwStatus.value = 'idle'
  }
}

// ── Two-step verification ───────────────────────────────────────────────────

// Turning on: get a secret, add it to an authenticator app, confirm with a
// code, then save the backup codes.
const setup = ref<{ secret: string; otpauthUrl: string }>()
const code = ref('')
const codeStatus = ref<InputCodeProps['status']>()
const codeText = ref<string>()
const backupCodes = ref<string[]>()
const starting = ref(false)

const secretGroups = computed(() => setup.value?.secret.match(/.{1,4}/g)?.join(' ') ?? '')

async function startSetup() {
  starting.value = true
  try {
    setup.value = await api.twoStepSetup()
    await focusFirst('#two-step-setup')
  } catch (e) {
    notify({ type: 'error', title: "Couldn't start setting up", description: message(e) })
  } finally {
    starting.value = false
  }
}

async function confirmSetup(value = code.value) {
  if (value.length < 6) {
    codeStatus.value = 'error'
    codeText.value = 'Enter all 6 digits'
    return
  }
  codeStatus.value = 'loading'
  codeText.value = 'Checking code…'
  try {
    const res = await api.twoStepEnable(value)
    backupCodes.value = res.backupCodes
    setup.value = undefined
    code.value = ''
    codeStatus.value = codeText.value = undefined
    await loadMe(true)
  } catch (e) {
    codeStatus.value = 'error'
    codeText.value = message(e)
    code.value = ''
  }
}

function cancelSetup() {
  setup.value = undefined
  code.value = ''
  codeStatus.value = codeText.value = undefined
}

// Turning off needs the password.
const turningOff = ref(false)
const offPassword = ref('')
const offError = ref<string>()
const offStatus = ref<ButtonStatus>('idle')

async function startTurnOff() {
  turningOff.value = true
  await focusFirst('#two-step-off')
}

async function turnOff() {
  offError.value = offPassword.value ? undefined : 'Enter your password'
  if (offError.value) return
  offStatus.value = 'loading'
  try {
    await api.twoStepDisable(offPassword.value)
    turningOff.value = false
    offPassword.value = ''
    backupCodes.value = undefined
    await loadMe(true)
    notify({ title: 'Two-step verification is off', description: 'Only your password is needed to sign in.' })
  } catch (e) {
    offError.value = message(e)
  } finally {
    offStatus.value = 'idle'
  }
}
</script>

<template>
  <PageHeader title="Security" description="How you prove it's you when you sign in." />

  <Card title="Password" :description="`Last changed ${formatDate(security.passwordChangedAt)}`">
    <template v-if="!changing" #actions>
      <Button size="sm" @click="changing = true; focusFirst('#password-form')">Change</Button>
    </template>
    <form v-if="changing" id="password-form" class="flex max-w-sm flex-col gap-4" novalidate @submit.prevent="savePassword">
      <InputPassword v-model="passwords.current" label="Current password" autocomplete="current-password" :error-text="pwErrors.current" />
      <InputPassword
        v-model="passwords.next"
        label="New password"
        helper="At least 12 characters. A few random words works well."
        autocomplete="new-password"
        :error-text="pwErrors.next"
      />
      <InputPassword v-model="passwords.confirm" label="New password again" autocomplete="new-password" :error-text="pwErrors.confirm" />
      <div class="flex gap-2">
        <Button type="submit" variant="primary" :status="pwStatus" loading-text="Saving">Save password</Button>
        <Button :disabled="pwStatus !== 'idle'" @click="resetPassword">Cancel</Button>
      </div>
    </form>
    <p v-else class="text-sm text-black/65">Use a password you don't use anywhere else. Changing it signs you out everywhere else.</p>
  </Card>

  <Card
    title="Two-step verification"
    :description="security.twoStep
      ? `On. You have ${security.backupCodesLeft} backup ${security.backupCodesLeft === 1 ? 'code' : 'codes'} left.`
      : 'Off. Turn it on so a stolen password isn\'t enough to get into your account.'"
  >
    <template v-if="!setup && !turningOff" #actions>
      <Button v-if="security.twoStep" size="sm" @click="startTurnOff">Turn off</Button>
      <Button v-else size="sm" variant="primary" :status="starting ? 'loading' : 'idle'" loading-text="Starting" @click="startSetup">
        Turn on
      </Button>
    </template>

    <!-- Backup codes, shown once, straight after turning it on. -->
    <div v-if="backupCodes" class="flex flex-col gap-3" role="status">
      <p class="text-sm font-bold">Two-step verification is on. Save these backup codes now.</p>
      <p class="text-sm text-black/65">
        Each works once, if you can't use your authenticator app. You won't see them again.
      </p>
      <ul class="grid grid-cols-2 gap-2 rounded bg-surface p-3 font-mono text-sm sm:grid-cols-5">
        <li v-for="c in backupCodes" :key="c">{{ c }}</li>
      </ul>
      <div><Button size="sm" @click="backupCodes = undefined">I've saved them</Button></div>
    </div>

    <form v-else-if="setup" id="two-step-setup" class="flex flex-col gap-4" @submit.prevent="confirmSetup()">
      <ol class="flex list-decimal flex-col gap-2 pl-5 text-sm">
        <li>
          Open an authenticator app on your phone and add an account.
          On this phone? <Link :href="setup.otpauthUrl">Add it to an authenticator app</Link>.
        </li>
        <li>
          Choose to enter a setup key, and type
          <span class="rounded bg-surface px-1.5 py-0.5 font-mono font-bold break-all">{{ secretGroups }}</span>
        </li>
        <li>Enter the 6-digit code it shows.</li>
      </ol>
      <InputCode
        v-model="code"
        label="Code from your authenticator app"
        :status="codeStatus"
        :status-text="codeText"
        :disabled="codeStatus === 'loading'"
        @complete="confirmSetup"
      />
      <div class="flex gap-2">
        <Button type="submit" variant="primary" :disabled="codeStatus === 'loading'">Turn on</Button>
        <Button @click="cancelSetup">Cancel</Button>
      </div>
    </form>

    <form v-else-if="turningOff" id="two-step-off" class="flex max-w-sm flex-col gap-4" novalidate @submit.prevent="turnOff">
      <InputPassword v-model="offPassword" label="Your password" autocomplete="current-password" :error-text="offError" />
      <div class="flex gap-2">
        <Button type="submit" variant="danger" :status="offStatus" loading-text="Turning off">Turn off</Button>
        <Button :disabled="offStatus !== 'idle'" @click="turningOff = false; offPassword = ''; offError = undefined">Cancel</Button>
      </div>
    </form>

    <p v-else class="text-sm text-black/65">
      After your password, you'll enter a 6-digit code from an authenticator app on your phone.
    </p>
  </Card>
</template>

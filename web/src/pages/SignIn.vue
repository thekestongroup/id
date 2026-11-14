<script setup lang="ts">
import { Lock, Mail } from '@lucide/vue'
import { Avatar, Button, type ButtonStatus, Card, Input, InputPassword, Link } from '@thekestongroup/ui'
import { reactive, ref } from 'vue'
import { RouterLink } from 'vue-router'
import AppName from '../components/AppName.vue'
import FlowState from '../components/FlowState.vue'
import KestonIdPage from '../components/KestonIdPage.vue'
import { api, ApiError } from '../lib/api'
import { useFlow } from '../lib/useFlow'

/**
 * Signing in to an app: its name and verification mark at the top, email and
 * password, and the terms people agree to by signing in. From the SignIn
 * story in Keston UI's "Examples/Keston ID". Without an app (signing in to
 * Keston ID itself) it says so instead.
 */
const { authRequestID, client, error: flowError, loading, next } = useFlow('sign-in')

const form = reactive({ email: '', password: '' })
const errors = reactive<{ email?: string; password?: string; form?: string }>({})
const status = ref<ButtonStatus>('idle')

async function signIn() {
  errors.email = form.email.trim() ? undefined : 'Enter your email address'
  errors.password = form.password ? undefined : 'Enter your password'
  errors.form = undefined
  if (errors.email || errors.password) return
  status.value = 'loading'
  try {
    const flow = await api.signIn(form.email.trim(), form.password, authRequestID.value)
    status.value = 'success'
    await next(flow)
  } catch (e) {
    status.value = 'idle'
    if (e instanceof ApiError && (e.field === 'email' || e.field === 'password')) errors[e.field] = e.message
    else errors.form = e instanceof Error ? e.message : String(e)
  }
}
</script>

<template>
  <KestonIdPage :brand="client ? 'tkg' : 'kestonId'">
    <FlowState :loading="loading" :error="flowError">
      <Card padding="md" :ui="{ footer: 'justify-center' }">
        <div class="flex flex-col gap-6">
          <div v-if="client" class="flex justify-center" aria-hidden="true">
            <Avatar :user="{ name: client.name }" size="lg" decorative />
          </div>

          <div class="flex flex-col gap-1 text-center">
            <AppName v-if="client" :client="client" />
            <h1 v-else tabindex="-1" class="text-xl font-bold outline-none">Sign in</h1>
            <p class="text-base">Sign in with your Keston account</p>
            <p v-if="client" class="text-sm text-black/65">An app by {{ client.publisher }}</p>
          </div>

          <form class="flex flex-col gap-4" novalidate @submit.prevent="signIn">
            <Input v-model="form.email" label="Email" type="email" autocomplete="username" :error-text="errors.email">
              <template #leading><Mail /></template>
            </Input>
            <!-- Forgot password? shows by the label but is reached by Tab after
                 the field, so people typing their password aren't sent to it. -->
            <InputPassword
              v-model="form.password"
              label="Password"
              autocomplete="current-password"
              :error-text="errors.password"
            >
              <template #leading><Lock /></template>
              <template #label-trailing>
                <Link :as="RouterLink" to="/forgot-password" class="text-black/65">Forgot password?</Link>
              </template>
            </InputPassword>
            <p v-if="errors.form" class="text-sm text-red" role="alert">{{ errors.form }}</p>
            <Button type="submit" variant="primary" :status="status" loading-text="Signing in" success-text="Signed in">
              Sign in
            </Button>
          </form>
        </div>
        <template #footer>
          <p class="text-center text-xs text-black/65">
            By signing in, you agree to our <Link href="#" new-tab>terms</Link>
            and <Link href="#" new-tab>privacy policy</Link>.
          </p>
        </template>
      </Card>
    </FlowState>
  </KestonIdPage>
</template>

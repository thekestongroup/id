<script setup lang="ts">
import { Mail, Ticket } from '@lucide/vue'
import { Button, type ButtonStatus, Card, Input, Link } from '@thekestongroup/ui'
import { reactive, ref } from 'vue'
import { RouterLink } from 'vue-router'
import FlowState from '../components/FlowState.vue'
import KestonIdPage from '../components/KestonIdPage.vue'
import { api, ApiError } from '../lib/api'
import { useFlow } from '../lib/useFlow'

/**
 * Signing in with a temporary access pass from an admin (e.g. after losing
 * a phone), instead of a password and MFA. They then set up MFA again.
 */
const { authRequestID, client, error: flowError, refused, loading, next } = useFlow('sign-in')

const form = reactive({ email: '', code: '' })
const errors = reactive<{ email?: string; code?: string; form?: string }>({})
const status = ref<ButtonStatus>('idle')

async function signIn() {
  errors.email = form.email.trim() ? undefined : 'Enter your email address'
  errors.code = form.code.trim() ? undefined : 'Enter your access pass'
  errors.form = undefined
  if (errors.email || errors.code) return
  status.value = 'loading'
  try {
    const flow = await api.signInWithPass(form.email.trim(), form.code, authRequestID.value)
    status.value = 'success'
    await next(flow)
  } catch (e) {
    status.value = 'idle'
    if (e instanceof ApiError && (e.field === 'email' || e.field === 'code')) errors[e.field] = e.message
    else errors.form = e instanceof Error ? e.message : String(e)
  }
}
</script>

<template>
  <KestonIdPage :brand="client ? 'tkg' : 'kestonId'">
    <FlowState :loading="loading" :error="flowError" :refused="refused">
      <Card>
        <div class="flex flex-col gap-6">
          <div class="flex flex-col gap-1">
            <h1 tabindex="-1" class="text-xl font-bold outline-none">Sign in with an access pass</h1>
            <p class="text-sm text-black/65">
              Use the access pass your organisation's IT team gave you. Next, you'll set up MFA again.
            </p>
          </div>
          <form class="flex flex-col gap-4" novalidate @submit.prevent="signIn">
            <Input v-model="form.email" label="Email" type="email" autocomplete="username" :error-text="errors.email">
              <template #leading><Mail /></template>
            </Input>
            <Input
              v-model="form.code"
              label="Access pass"
              helper="Like ABCD-EFGH-JKLM-NPQR"
              autocomplete="one-time-code"
              autocapitalize="characters"
              spellcheck="false"
              :error-text="errors.code"
            >
              <template #leading><Ticket /></template>
            </Input>
            <p v-if="errors.form" class="text-sm text-red" role="alert">{{ errors.form }}</p>
            <Button type="submit" variant="primary" :status="status" loading-text="Signing in" success-text="Signed in">
              Sign in
            </Button>
          </form>
        </div>
      </Card>
      <p class="text-center text-sm">
        <Link :as="RouterLink" :to="{ path: '/sign-in', query: $route.query }">Sign in with your password</Link>
      </p>
    </FlowState>
  </KestonIdPage>
</template>

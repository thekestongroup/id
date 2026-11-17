<script setup lang="ts">
import { ArrowLeftRight } from '@lucide/vue'
import { Avatar, Button, type ButtonStatus, Card, Checkbox, Divider, Link } from '@thekestongroup/ui'
import { computed, reactive, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import AppName from '../components/AppName.vue'
import FlowState from '../components/FlowState.vue'
import KestonIdPage from '../components/KestonIdPage.vue'
import { api } from '../lib/api'
import { scopeIcon } from '../lib/scopes'
import { useFlow } from '../lib/useFlow'

/**
 * The OAuth 2.0 consent prompt: which app is asking, who's signed in, what it
 * will get, and Allow / Cancel. Scopes the app needs are listed; the others
 * can be unticked before allowing. Allow sends the person back to the app
 * with a code; Cancel with error=access_denied. From the OAuthConsent story
 * in Keston UI's "Examples/Keston ID".
 */
const { authRequestID, flow, client, error: flowError, refused, loading } = useFlow('consent')
const router = useRouter()

const user = computed(() => flow.value?.user)
const required = computed(() => flow.value?.scopes?.required ?? [])
const optionalScopes = computed(() => flow.value?.scopes?.optional ?? [])
const optional = reactive<Record<string, boolean>>({})
watch(optionalScopes, (list) => list.forEach((s) => (optional[s.id] ??= true)), { immediate: true })

const allowStatus = ref<ButtonStatus>('idle')
const error = ref<string>()

async function allow() {
  allowStatus.value = 'loading'
  error.value = undefined
  try {
    const granted = optionalScopes.value.filter((s) => optional[s.id]).map((s) => s.id)
    const res = await api.consent(authRequestID.value!, granted)
    allowStatus.value = 'success'
    window.location.assign(res.redirect!)
  } catch (e) {
    allowStatus.value = 'idle'
    error.value = e instanceof Error ? e.message : String(e)
  }
}

function cancel() {
  window.location.assign(`/authorize/deny?id=${encodeURIComponent(authRequestID.value!)}`)
}

function switchAccount() {
  router.push({ path: '/choose-account', query: { authRequestID: authRequestID.value } })
}
</script>

<template>
  <KestonIdPage brand="tkg">
    <FlowState :loading="loading" :error="flowError" :refused="refused">
      <Card v-if="client && user" padding="md">
        <div class="flex flex-col gap-6">
          <div class="flex items-center justify-center gap-3" aria-hidden="true">
            <Avatar :user="{ name: client.name }" size="lg" decorative />
            <ArrowLeftRight class="size-5 text-black/55" />
            <Avatar :user="user" size="lg" decorative />
          </div>

          <div class="flex flex-col gap-1 text-center">
            <AppName :client="client" />
            <p class="text-base">wants to access your Keston account</p>
            <p class="text-sm text-black/65">An app by {{ client.publisher }}</p>
          </div>

          <!-- Who's signed in, as a small Card in a row. -->
          <Card as="div" padding="sm" :ui="{ body: 'flex-row items-center justify-between gap-3 p-3' }">
            <div class="flex min-w-0 items-center gap-2">
              <Avatar :user="user" size="sm" decorative />
              <div class="flex min-w-0 flex-col">
                <span class="truncate text-sm font-bold">{{ user.name }}</span>
                <span class="truncate text-xs text-black/65">{{ user.email }}</span>
              </div>
            </div>
            <Button size="sm" class="shrink-0" @click="switchAccount">Switch account</Button>
          </Card>

          <div v-if="required.length" class="flex flex-col gap-3">
            <h2 class="text-sm font-bold">This will let {{ client.name }}:</h2>
            <ul class="flex flex-col gap-3">
              <li v-for="scope in required" :key="scope.id" class="flex items-start gap-3">
                <component
                  :is="scopeIcon(scope.icon)"
                  class="mt-0.5 size-4 shrink-0 text-black/65"
                  aria-hidden="true"
                />
                <div class="flex flex-col gap-0.5">
                  <span class="text-sm">{{ scope.label }}</span>
                  <span class="text-xs text-black/65">{{ scope.id === 'email' ? user.email : scope.description }}</span>
                </div>
              </li>
            </ul>
          </div>

          <div v-if="optionalScopes.length" class="flex flex-col gap-3">
            <h2 class="text-sm font-bold">You can choose whether it can also:</h2>
            <Checkbox
              v-for="scope in optionalScopes"
              :key="scope.id"
              v-model="optional[scope.id]"
              :label="scope.label"
              :description="scope.description"
            />
          </div>

          <Divider />

          <p class="text-xs text-black/65">
            You'll be sent to <span class="font-bold text-black">{{ client.redirectHost }}</span>. Make sure you trust
            {{ client.name }}: read its
            <Link :href="client.privacyUrl || '#'" new-tab>privacy policy</Link>
            and
            <Link :href="client.termsUrl || '#'" new-tab>terms</Link>. You can remove its access at any time in your
            Keston account.
          </p>

          <p v-if="error" class="text-sm text-red" role="alert">{{ error }}</p>

          <div class="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
            <Button :disabled="allowStatus !== 'idle'" @click="cancel">Cancel</Button>
            <Button
              variant="primary"
              :status="allowStatus"
              loading-text="Allowing"
              success-text="Allowed"
              @click="allow"
            >
              Allow
            </Button>
          </div>
        </div>
      </Card>
    </FlowState>
  </KestonIdPage>
</template>

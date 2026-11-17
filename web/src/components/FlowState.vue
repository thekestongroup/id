<script setup lang="ts">
import { Button, Card, Link, Spinner } from '@thekestongroup/ui'
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { RouterLink } from 'vue-router'
import RequestAccessForm from './RequestAccessForm.vue'

/**
 * While a sign-in page asks the server where it is in the flow: a spinner,
 * or why it can't go on (e.g. the link from the app has expired).
 */
defineProps<{ loading: boolean; error?: string; refused?: { clientId: string; clientName: string; pending: boolean } }>()
const { t } = useI18n()
const asking = ref(false)
const sent = ref(false)
</script>

<template>
  <Card v-if="error">
    <div class="flex flex-col gap-2">
      <h1 tabindex="-1" class="text-xl font-bold outline-none">Can't sign in from here</h1>
      <p class="text-sm" role="alert">{{ error }}</p>
      <template v-if="refused">
        <p v-if="refused.pending || sent" class="text-sm text-black/65">{{ t('appRequests.pendingHint') }}</p>
        <RequestAccessForm
          v-else-if="asking"
          :client-id="refused.clientId"
          :client-name="refused.clientName"
          @sent="sent = true"
          @cancel="asking = false"
        />
        <div v-else>
          <Button size="sm" @click="asking = true">{{ t('appRequests.request') }}</Button>
        </div>
      </template>
      <p class="text-sm text-black/65">Or go to <Link :as="RouterLink" to="/account">your Keston account</Link>.</p>
    </div>
  </Card>
  <div v-else-if="loading" class="flex justify-center py-12"><Spinner label="Loading" /></div>
  <slot v-else />
</template>

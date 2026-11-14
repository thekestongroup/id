<script setup lang="ts">
import { Card, Link, Spinner } from '@thekestongroup/ui'
import { RouterLink } from 'vue-router'

/**
 * While a sign-in page asks the server where it is in the flow: a spinner,
 * or why it can't go on (e.g. the link from the app has expired).
 */
defineProps<{ loading: boolean; error?: string }>()
</script>

<template>
  <Card v-if="error">
    <div class="flex flex-col gap-2">
      <h1 tabindex="-1" class="text-xl font-bold outline-none">Can't sign in from here</h1>
      <p class="text-sm" role="alert">{{ error }}</p>
      <p class="text-sm text-black/65">Or go to <Link :as="RouterLink" to="/account">your Keston account</Link>.</p>
    </div>
  </Card>
  <div v-else-if="loading" class="flex justify-center py-12"><Spinner label="Loading" /></div>
  <slot v-else />
</template>

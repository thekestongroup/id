<script setup lang="ts">
import { Badge, Button, Card, PageHeader, formatDate } from '@thekestongroup/ui'
import { computed, ref } from 'vue'
import ChangePasswordSlideover from '../../components/ChangePasswordSlideover.vue'
import MfaOffSlideover from '../../components/MfaOffSlideover.vue'
import MfaSetupSlideover from '../../components/MfaSetupSlideover.vue'
import { me } from '../../lib/session'

/** How you prove it's you. Each change happens in its own Slideover. */
const security = computed(() => me.value!.security)
const changingPassword = ref(false)
const settingUp = ref(false)
const turningOff = ref(false)

const backupLeft = computed(() => {
  const n = security.value.backupCodesLeft
  return n === 1 ? '1 backup code left' : `${n} backup codes left`
})
</script>

<template>
  <PageHeader title="Security" description="How you prove it's you when you sign in." />

  <Card title="Password" :description="`Last changed ${formatDate(security.passwordChangedAt)}`">
    <template #actions>
      <Button size="sm" @click="changingPassword = true">Change</Button>
    </template>
    <p class="text-sm text-black/65">Use a password you don't use anywhere else.</p>
  </Card>

  <!-- The On / Off badge sits beside the title, as in PageHeader's #badge.
       With the header slot instead of title, the card is named by its h2 here. -->
  <Card as="section" aria-labelledby="mfa-heading">
    <template #header>
      <div class="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
        <h2 id="mfa-heading" class="text-base font-bold">Multi-factor authentication (MFA)</h2>
        <Badge v-if="security.mfa" size="sm" color="green">On</Badge>
        <Badge v-else size="sm" color="yellow">Off</Badge>
      </div>
    </template>
    <template #actions>
      <Button v-if="security.mfa" size="sm" @click="turningOff = true">Turn off</Button>
      <Button v-else size="sm" variant="primary" @click="settingUp = true">Turn on</Button>
    </template>
    <p v-if="security.mfa" class="text-sm text-black/65">
      After your password, you enter a code from your authenticator app. {{ backupLeft }}.
    </p>
    <p v-else class="text-sm text-black/65">
      Turn it on so a stolen password isn't enough to get into your account. You'll need an authenticator app on your
      phone.
    </p>
  </Card>

  <ChangePasswordSlideover v-model:open="changingPassword" />
  <MfaSetupSlideover v-model:open="settingUp" />
  <MfaOffSlideover v-model:open="turningOff" />
</template>

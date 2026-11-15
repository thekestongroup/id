<script setup lang="ts">
import { Badge, Button, Card, PageHeader, formatDate } from '@thekestongroup/ui'
import { computed, ref } from 'vue'
import ChangePasswordSlideover from '../../components/ChangePasswordSlideover.vue'
import MfaOffSlideover from '../../components/MfaOffSlideover.vue'
import MfaSetupSlideover from '../../components/MfaSetupSlideover.vue'
import PasskeysCard from '../../components/PasskeysCard.vue'
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
    <!-- MFA is on with an authenticator app or any passkey (see the card
         below); the buttons here are for the authenticator app. -->
    <template #actions>
      <Button v-if="security.authenticatorApp" size="sm" @click="turningOff = true">
        {{ security.passkeys ? 'Turn off app' : 'Turn off' }}
      </Button>
      <Button v-else size="sm" :variant="security.mfa ? 'basic' : 'primary'" @click="settingUp = true">
        {{ security.passkeys ? 'Add app' : 'Turn on' }}
      </Button>
    </template>
    <p v-if="security.authenticatorApp && security.passkeys" class="text-sm text-black/65">
      After your password, you use a passkey or enter a code from your authenticator app. {{ backupLeft }}.
    </p>
    <p v-else-if="security.authenticatorApp" class="text-sm text-black/65">
      After your password, you enter a code from your authenticator app. {{ backupLeft }}.
    </p>
    <p v-else-if="security.passkeys" class="text-sm text-black/65">
      After your password, you use one of your passkeys. You can add an authenticator app too, in case you can't use
      them.
    </p>
    <p v-else class="text-sm text-black/65">
      Turn it on so a stolen password isn't enough to get into your account. You'll need an authenticator app on your
      phone, or add a passkey below.
    </p>
  </Card>

  <PasskeysCard />

  <ChangePasswordSlideover v-model:open="changingPassword" />
  <MfaSetupSlideover v-model:open="settingUp" />
  <MfaOffSlideover v-model:open="turningOff" :passkeys="security.passkeys" />
</template>

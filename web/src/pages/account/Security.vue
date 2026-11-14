<script setup lang="ts">
import { Badge, Button, Card, PageHeader, formatDate } from '@thekestongroup/ui'
import { computed, ref } from 'vue'
import ChangePasswordSlideover from '../../components/ChangePasswordSlideover.vue'
import TwoStepOffSlideover from '../../components/TwoStepOffSlideover.vue'
import TwoStepSetupSlideover from '../../components/TwoStepSetupSlideover.vue'
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

  <Card title="Two-step verification">
    <template #actions>
      <Button v-if="security.twoStep" size="sm" @click="turningOff = true">Turn off</Button>
      <Button v-else size="sm" variant="primary" @click="settingUp = true">Turn on</Button>
    </template>
    <div class="flex flex-col gap-2">
      <div>
        <Badge v-if="security.twoStep" color="green">On</Badge>
        <Badge v-else color="yellow">Off</Badge>
      </div>
      <p v-if="security.twoStep" class="text-sm text-black/65">
        After your password, you enter a code from your authenticator app. {{ backupLeft }}.
      </p>
      <p v-else class="text-sm text-black/65">
        Turn it on so a stolen password isn't enough to get into your account. You'll need an authenticator app on
        your phone.
      </p>
    </div>
  </Card>

  <ChangePasswordSlideover v-model:open="changingPassword" />
  <TwoStepSetupSlideover v-model:open="settingUp" />
  <TwoStepOffSlideover v-model:open="turningOff" />
</template>

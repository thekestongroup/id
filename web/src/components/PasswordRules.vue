<script setup lang="ts">
import { Checklist } from '@thekestongroup/ui'
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import type { PasswordRule } from '../lib/api'
import { ruleMet } from '../lib/passwordRules'

/**
 * What a new password must meet, ticked off as it's typed. The rules are the
 * organisation's; unmet ones turn red after a failed attempt (`invalid`).
 * The server still checks, including the common-passwords list.
 */
const props = defineProps<{
  rules: PasswordRule[]
  password: string
  invalid?: boolean
}>()
const { t } = useI18n()

const items = computed(() => {
  const list = props.rules
    .filter((r) => r.id !== 'common')
    .map((r) => ({ label: t(`passwordRules.${r.id}`, { n: r.min ?? 0 }, r.min ?? 0), done: ruleMet(r, props.password) }))
  if (props.rules.some((r) => r.id === 'common')) {
    list.push({ label: t('passwordRules.common'), done: props.password.length > 0 })
  }
  return list
})
defineExpose({ allMet: () => props.rules.every((r) => ruleMet(r, props.password)) })
</script>

<template>
  <div class="flex flex-col gap-2">
    <p class="text-sm font-medium">{{ t('passwordRules.heading') }}</p>
    <Checklist :items="items" :invalid="invalid" />
  </div>
</template>

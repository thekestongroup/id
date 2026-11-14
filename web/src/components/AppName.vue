<script setup lang="ts">
import { BadgeCheck } from '@lucide/vue'
import { Link, Popover } from '@thekestongroup/ui'
import type { ClientView } from '../lib/api'

/**
 * The app's name as the page heading, with its verification mark beside it
 * (outside the heading, so the mark's "More info" link isn't part of it).
 * The mark's panel is rendered in place, so Tab goes from the mark straight
 * to "More info" once it's open. Owned apps get a Keston blue tick; verified
 * ones the brighter blue. From Keston UI's "Examples/Keston ID" stories.
 */
withDefaults(defineProps<{ client: ClientView; as?: 'h1' | 'h2'; headingClass?: string; center?: boolean }>(), {
  as: 'h1',
  headingClass: 'text-xl font-bold',
  center: true,
})
</script>

<template>
  <div class="flex items-center gap-1.5" :class="center && 'justify-center'">
    <component :is="as" tabindex="-1" :class="headingClass" class="outline-none">{{ client.name }}</component>
    <Popover
      v-if="client.verification !== 'none'"
      mode="hover"
      :portal="false"
      :open-delay="200"
      :close-delay="150"
      arrow
      :content="{ side: 'top', sideOffset: 6 }"
      :ui="{ content: 'w-max px-3 py-2' }"
    >
      <button
        type="button"
        aria-label="Verified by The Keston Group."
        :class="client.verification === 'owned' ? 'text-kblue' : 'text-blue'"
        class="flex cursor-pointer rounded-full outline-2 outline-offset-1 outline-transparent focus-visible:outline-focus"
      >
        <BadgeCheck class="size-5" aria-hidden="true" />
      </button>
      <template #content>
        <!-- One line, as narrow as its text. -->
        <div class="flex items-center gap-2 text-sm whitespace-nowrap">
          <p class="font-bold">Verified by The Keston Group.</p>
          <Link href="#" new-tab>More info<span class="sr-only"> about verification marks</span></Link>
        </div>
      </template>
    </Popover>
  </div>
</template>

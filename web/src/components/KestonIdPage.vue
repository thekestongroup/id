<script setup lang="ts">
import { ShieldCheck } from '@lucide/vue'
import { Footer } from '@thekestongroup/ui'
import { footer } from '../lib/footer'

/**
 * Every Keston ID page: a narrow column centred on the grey background, with
 * the branding above the card. From Keston UI's "Examples/Keston ID" stories.
 *
 * Pages an app sends people to show the organisation's logo (for now always
 * The Keston Group); Keston ID's own pages show Keston ID's. The TKG square
 * stands in for the real logo: swap it for the SVG when there is one.
 */
withDefaults(defineProps<{ brand?: 'tkg' | 'kestonId' }>(), { brand: 'kestonId' })
</script>

<template>
  <div class="flex min-h-screen flex-col bg-background text-black">
    <div class="flex flex-1 flex-col items-center px-4 py-12">
      <main class="flex w-full max-w-100 flex-col gap-6">
        <div v-if="brand === 'tkg'" class="flex items-center justify-center gap-2 text-primary">
          <span
            class="flex size-8 items-center justify-center rounded bg-primary text-xs font-bold text-white"
            aria-hidden="true"
            >TKG</span
          >
          <span class="text-lg font-bold">The Keston Group</span>
        </div>
        <div v-else class="flex items-center justify-center gap-2 text-primary">
          <ShieldCheck class="size-6" aria-hidden="true" />
          <span class="text-lg font-bold">Keston ID</span>
        </div>

        <slot />
      </main>
    </div>
    <!-- Help & support, Privacy Policy and Terms & Conditions, the app's version and build, and the copyright. -->
    <Footer v-bind="footer" />
  </div>
</template>

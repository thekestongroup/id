<script setup lang="ts">
import { ShieldCheck } from '@lucide/vue'
import { Link } from '@thekestongroup/ui'

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
  <div class="flex min-h-screen flex-col items-center bg-background px-4 py-12 text-black">
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

      <nav aria-label="Legal and help" class="flex items-center justify-center gap-2 text-xs text-black/65">
        <Link href="#" new-tab class="py-1">Privacy</Link>
        <span aria-hidden="true">·</span>
        <Link href="#" new-tab class="py-1">Terms</Link>
        <span aria-hidden="true">·</span>
        <Link href="#" new-tab class="py-1">Help</Link>
      </nav>
    </main>
  </div>
</template>

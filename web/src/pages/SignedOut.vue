<script setup lang="ts">
import { Card, Link } from '@thekestongroup/ui'
import { RouterLink } from 'vue-router'
import KestonIdPage from '../components/KestonIdPage.vue'

/** Where signing out of an app ends when it gives no address to return to. */
</script>

<template>
  <KestonIdPage>
    <Card>
      <div class="flex flex-col gap-2">
        <h1 tabindex="-1" class="text-xl font-bold outline-none">You've signed out</h1>
        <p class="text-sm">You've signed out of Keston ID. You can close this tab.</p>
      </div>
    </Card>
    <p class="text-center text-sm"><Link :as="RouterLink" to="/sign-in">Sign in again</Link></p>
  </KestonIdPage>
</template>

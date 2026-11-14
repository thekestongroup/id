<script setup lang="ts">
import { Card, Link } from '@thekestongroup/ui'
import { RouterLink } from 'vue-router'
import KestonIdPage from '../components/KestonIdPage.vue'

// Reset links by email need an email service, which Keston ID doesn't have
// yet. Until then, schools reset passwords for their people.
</script>

<template>
  <KestonIdPage>
    <Card>
      <div class="flex flex-col gap-2">
        <h1 tabindex="-1" class="text-xl font-bold outline-none">Forgotten your password?</h1>
        <p class="text-sm">
          Ask your school or organisation's IT team to reset it. They'll give you a new password to sign in with, which
          you can then change in your Keston account.
        </p>
      </div>
    </Card>
    <p class="text-center text-sm"><Link :as="RouterLink" to="/sign-in">Back to sign in</Link></p>
  </KestonIdPage>
</template>

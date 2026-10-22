<script setup lang="ts">
import { ref } from 'vue'
import Button from '@thekestongroup/ui/components/Button.vue'
import Input from '@thekestongroup/ui/components/Input.vue'
import Label from '@thekestongroup/ui/components/Label.vue'

const params = new URLSearchParams(window.location.search)
const returnTo = params.get('return_to') ?? ''
const error = params.get('error')

const username = ref('')
const password = ref('')
</script>

<template>
  <div class="flex min-h-screen items-center justify-center bg-neutral-100 px-4">
    <div class="w-full max-w-sm rounded-lg border border-neutral-200 bg-white p-8 shadow-sm">
      <div class="mb-8 text-center">
        <h1 class="text-2xl font-bold text-neutral-900">Keston ID</h1>
        <p class="mt-2 text-sm text-neutral-500">Sign in to continue.</p>
      </div>

      <form method="post" action="/login" class="space-y-4">
        <input type="hidden" name="return_to" :value="returnTo" />

        <div class="space-y-1.5">
          <Label for="username">Username</Label>
          <Input id="username" name="username" v-model="username" autocomplete="username" placeholder="admin" />
        </div>

        <div class="space-y-1.5">
          <Label for="password">Password</Label>
          <Input
            id="password"
            name="password"
            v-model="password"
            type="password"
            autocomplete="current-password"
            placeholder="••••••••"
          />
        </div>

        <p v-if="error" class="text-sm text-red-600">Invalid username or password.</p>

        <Button type="submit" class="w-full">Sign in</Button>
      </form>

      <p class="mt-6 text-center text-xs text-neutral-400">Demo credentials: admin / password</p>
    </div>
  </div>
</template>

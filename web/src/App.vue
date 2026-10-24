<script setup lang="ts">
import { ref } from 'vue'
import AccountsPage from './pages/AccountsPage.vue'
import ConsentPage from './pages/ConsentPage.vue'
import LoginPage from './pages/LoginPage.vue'

const path = window.location.pathname
const isConsent = ref(path === '/consent')
const isAccounts = ref(path === '/logout')
</script>

<template>
  <AccountsPage v-if="isAccounts" />
  <ConsentPage v-else-if="isConsent" />
  <LoginPage v-else />
</template>

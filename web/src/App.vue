<script setup lang="ts">
import { ref } from 'vue'
import ConsentPage from './pages/ConsentPage.vue'
import LoginPage from './pages/LoginPage.vue'

const isConsent = ref(window.location.pathname === '/consent')
</script>

<template>
  <LoginPage v-if="!isConsent" />
  <ConsentPage v-else />
</template>

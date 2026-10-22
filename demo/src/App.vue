<script setup lang="ts">
import { ref } from 'vue'
import CallbackPage from './pages/CallbackPage.vue'
import DemoPage from './pages/DemoPage.vue'

const isCallback = ref(window.location.pathname === '/callback')
</script>

<template>
  <CallbackPage v-if="isCallback" />
  <DemoPage v-else />
</template>

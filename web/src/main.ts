import { createApp } from 'vue'
import App from './App.vue'
import { reloadOnStaleBuild } from './lib/staleBuild'
import { i18n } from './i18n'
import { router } from './router'
import './style.css'

reloadOnStaleBuild(router)
createApp(App).use(router).use(i18n).mount('#app')

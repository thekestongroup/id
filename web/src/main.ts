import { createApp } from 'vue'
import App from './App.vue'
import { reloadOnStaleBuild } from './lib/staleBuild'
import { router } from './router'
import './style.css'

reloadOnStaleBuild(router)
createApp(App).use(router).mount('#app')

import { createApp } from 'vue'
import { ElButton, ElTag } from 'element-plus'
import 'element-plus/dist/index.css'

import App from './App.vue'
import { pinia } from './stores'
import { router } from './router'
import './styles.css'

createApp(App)
  .use(pinia)
  .use(router)
  .use(ElButton)
  .use(ElTag)
  .mount('#app')

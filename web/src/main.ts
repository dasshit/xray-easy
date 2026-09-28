import { createApp } from 'vue'
import App from './App.vue'
import { xrayEasyApi } from './infrastructure/xrayEasyApi'
import { xrayEasyGatewayKey } from './presentation/api'
import './style.css'

createApp(App).provide(xrayEasyGatewayKey, xrayEasyApi).mount('#app')

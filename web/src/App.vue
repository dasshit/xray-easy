<script setup lang="ts">
import { onMounted, ref } from 'vue'

type SetupStatus = { initialized: boolean; username?: string }
type Admin = { username: string }

const setup = ref<SetupStatus | null>(null)
const admin = ref<Admin | null>(null)
const error = ref('')
const busy = ref(false)
const language = ref<'en' | 'ru'>(navigator.language.toLowerCase().startsWith('ru') ? 'ru' : 'en')
const setupForm = ref({ username: 'admin', password: '', publicHost: '', publicPort: 443 })
const loginForm = ref({ username: 'admin', password: '' })

const text = {
  en: {
    title: 'Xray-easy', setup: 'Initial setup', login: 'Administrator login', username: 'Username', password: 'Password', host: 'Public host or IPv4', port: 'Public port', create: 'Create administrator', signIn: 'Sign in', ready: 'Control plane is ready', next: 'The device renderer and REALITY settings are coming in the next slice.', logout: 'Sign out', language: 'Русский',
  },
  ru: {
    title: 'Xray-easy', setup: 'Первичная настройка', login: 'Вход администратора', username: 'Имя пользователя', password: 'Пароль', host: 'Публичный адрес или IPv4', port: 'Публичный порт', create: 'Создать администратора', signIn: 'Войти', ready: 'Control plane готов', next: 'Renderer устройств и настройки REALITY появятся в следующем срезе.', logout: 'Выйти', language: 'English',
  },
}

const t = () => text[language.value]

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(url, { headers: { 'Content-Type': 'application/json' }, ...options })
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`)
  return payload as T
}

async function load() {
  error.value = ''
  try {
    setup.value = await request<SetupStatus>('/api/setup/status')
    if (setup.value.initialized) admin.value = await request<Admin>('/api/me')
  } catch (cause) {
    if (setup.value?.initialized) admin.value = null
    else error.value = cause instanceof Error ? cause.message : 'Request failed'
  }
}

async function initialize() {
  busy.value = true
  error.value = ''
  try {
    await request('/api/setup/initialize', { method: 'POST', body: JSON.stringify({ username: setupForm.value.username, password: setupForm.value.password, public_host: setupForm.value.publicHost, public_port: setupForm.value.publicPort }) })
    loginForm.value.username = setupForm.value.username
    setup.value = { initialized: true }
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : 'Request failed'
  } finally { busy.value = false }
}

async function login() {
  busy.value = true
  error.value = ''
  try {
    admin.value = await request<Admin>('/api/auth/login', { method: 'POST', body: JSON.stringify(loginForm.value) })
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : 'Request failed'
  } finally { busy.value = false }
}

async function logout() {
  await request('/api/auth/logout', { method: 'POST' })
  admin.value = null
}

onMounted(load)
</script>

<template>
  <main class="shell">
    <header><strong>{{ t().title }}</strong><button class="language" @click="language = language === 'en' ? 'ru' : 'en'">{{ t().language }}</button></header>
    <section class="card" v-if="error"><p class="error">{{ error }}</p></section>
    <section class="card" v-if="!setup?.initialized">
      <h1>{{ t().setup }}</h1>
      <label>{{ t().username }}<input v-model="setupForm.username" autocomplete="username" /></label>
      <label>{{ t().password }}<input v-model="setupForm.password" type="password" autocomplete="new-password" /></label>
      <label>{{ t().host }}<input v-model="setupForm.publicHost" placeholder="vpn.example.com" /></label>
      <label>{{ t().port }}<input v-model.number="setupForm.publicPort" type="number" min="1" max="65535" /></label>
      <button :disabled="busy" @click="initialize">{{ t().create }}</button>
    </section>
    <section class="card" v-else-if="!admin">
      <h1>{{ t().login }}</h1>
      <label>{{ t().username }}<input v-model="loginForm.username" autocomplete="username" /></label>
      <label>{{ t().password }}<input v-model="loginForm.password" type="password" autocomplete="current-password" /></label>
      <button :disabled="busy" @click="login">{{ t().signIn }}</button>
    </section>
    <section class="card" v-else>
      <div class="card-title"><h1>{{ t().ready }}</h1><button class="secondary" @click="logout">{{ t().logout }}</button></div>
      <p>{{ t().next }}</p>
    </section>
  </main>
</template>

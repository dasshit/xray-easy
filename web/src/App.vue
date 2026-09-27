<script setup lang="ts">
import { onMounted, ref } from 'vue'

type SetupStatus = { initialized: boolean; public_port?: number }
type Admin = { username: string }
type Client = { id: string; name: string; enabled: boolean; revoked: boolean; fingerprint?: string }

const setup = ref<SetupStatus | null>(null)
const admin = ref<Admin | null>(null)
const clients = ref<Client[]>([])
const newDevice = ref({ name: '', fingerprint: '' })
const selectedProfile = ref<{ client_id: string; uri: string; json: unknown } | null>(null)
const error = ref('')
const busy = ref(false)
const language = ref<'en' | 'ru'>(navigator.language.toLowerCase().startsWith('ru') ? 'ru' : 'en')
const setupForm = ref({ username: 'admin', password: '', publicHost: '', publicPort: 443, realityTarget: 'www.cloudflare.com:443', realitySNI: 'www.cloudflare.com' })
const loginForm = ref({ username: 'admin', password: '' })

const text = {
  en: {
    title: 'Xray-easy', setup: 'Initial setup', login: 'Administrator login', username: 'Username', password: 'Password', host: 'Public host or IPv4', port: 'Public port (from Compose)', target: 'REALITY target', sni: 'REALITY SNI', create: 'Create administrator', signIn: 'Sign in', ready: 'Devices', newDevice: 'Device name', fingerprint: 'Fingerprint', createDevice: 'Create device', profile: 'Profile', qr: 'QR code', download: 'Download JSON', enabled: 'enabled', disabled: 'disabled', revoked: 'revoked', enable: 'Enable', disable: 'Disable', revoke: 'Revoke', logout: 'Sign out', language: 'Русский',
  },
  ru: {
    title: 'Xray-easy', setup: 'Первичная настройка', login: 'Вход администратора', username: 'Имя пользователя', password: 'Пароль', host: 'Публичный адрес или IPv4', port: 'Публичный порт (из Compose)', target: 'REALITY target', sni: 'REALITY SNI', create: 'Создать администратора', signIn: 'Войти', ready: 'Устройства', newDevice: 'Имя устройства', fingerprint: 'Fingerprint', createDevice: 'Создать устройство', profile: 'Профиль', qr: 'QR-код', download: 'Скачать JSON', enabled: 'включено', disabled: 'выключено', revoked: 'отозвано', enable: 'Включить', disable: 'Выключить', revoke: 'Отозвать', logout: 'Выйти', language: 'English',
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
    if (setup.value.public_port) setupForm.value.publicPort = setup.value.public_port
    if (setup.value.initialized) {
      admin.value = await request<Admin>('/api/me')
      clients.value = await request<Client[]>('/api/clients')
    }
  } catch (cause) {
    if (setup.value?.initialized) admin.value = null
    else error.value = cause instanceof Error ? cause.message : 'Request failed'
  }
}

async function initialize() {
  busy.value = true
  error.value = ''
  try {
    await request('/api/setup/initialize', { method: 'POST', body: JSON.stringify({ username: setupForm.value.username, password: setupForm.value.password, public_host: setupForm.value.publicHost, public_port: setupForm.value.publicPort, reality_target: setupForm.value.realityTarget, reality_sni: setupForm.value.realitySNI }) })
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

async function createDevice() {
  busy.value = true; error.value = ''
  try {
    const created = await request<Client>('/api/clients', { method: 'POST', body: JSON.stringify({ name: newDevice.value.name, fingerprint: newDevice.value.fingerprint || undefined }) })
    clients.value.push(created)
    newDevice.value = { name: '', fingerprint: '' }
    await showProfile(created)
  } catch (cause) { error.value = cause instanceof Error ? cause.message : 'Request failed' }
  finally { busy.value = false }
}

async function showProfile(client: Client) {
  selectedProfile.value = await request<{ client_id: string; uri: string; json: unknown }>(`/api/clients/${client.id}/profile?format=uri`)
}

async function changeState(client: Client, action: 'enable' | 'disable' | 'revoke') {
  busy.value = true; error.value = ''
  try {
    const updated = await request<Client>(`/api/clients/${client.id}/${action}`, { method: 'POST' })
    const index = clients.value.findIndex(item => item.id === client.id)
    if (index >= 0) clients.value[index] = updated
  } catch (cause) { error.value = cause instanceof Error ? cause.message : 'Request failed' }
  finally { busy.value = false }
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
      <label>{{ t().port }}<input v-model.number="setupForm.publicPort" type="number" readonly /></label>
      <label>{{ t().target }}<input v-model="setupForm.realityTarget" placeholder="www.cloudflare.com:443" /></label>
      <label>{{ t().sni }}<input v-model="setupForm.realitySNI" placeholder="www.cloudflare.com" /></label>
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
      <div class="device-create"><input v-model="newDevice.name" :placeholder="t().newDevice" @keyup.enter="createDevice" /><select v-model="newDevice.fingerprint"><option value="">chrome</option><option value="safari">safari</option><option value="ios">ios</option><option value="firefox">firefox</option><option value="edge">edge</option></select><button :disabled="busy || !newDevice.name" @click="createDevice">{{ t().createDevice }}</button></div>
      <ul class="devices"><li v-for="client in clients" :key="client.id"><span><strong>{{ client.name }}</strong><small>{{ client.revoked ? t().revoked : client.enabled ? t().enabled : t().disabled }}</small></span><span><button class="secondary" @click="showProfile(client)">{{ t().profile }}</button><button v-if="!client.revoked && !client.enabled" class="secondary" @click="changeState(client, 'enable')">{{ t().enable }}</button><button v-if="!client.revoked && client.enabled" class="secondary" @click="changeState(client, 'disable')">{{ t().disable }}</button><button v-if="!client.revoked" class="danger" @click="changeState(client, 'revoke')">{{ t().revoke }}</button></span></li></ul>
      <div v-if="selectedProfile" class="profile"><label>VLESS URI<textarea readonly :value="selectedProfile.uri"></textarea></label><img :src="`/api/clients/${selectedProfile.client_id}/profile?format=qr`" :alt="t().qr" /><a :href="`/api/clients/${selectedProfile.client_id}/profile?format=json`">{{ t().download }}</a></div>
    </section>
  </main>
</template>

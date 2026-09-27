<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'

type SetupStatus = { initialized: boolean; public_port?: number }
type Admin = { username: string; totp_enabled?: boolean; recovery_codes_remaining?: number }
type Client = { id: string; name: string; enabled: boolean; revoked: boolean; fingerprint?: string; online: boolean; last_seen?: string; upload_bytes: number; download_bytes: number }
type TOTPStatus = { enabled: boolean; recovery_codes_remaining: number }
type TOTPSetup = { setup_token: string; secret: string; otpauth_uri: string; recovery_codes: string[]; expires_in: number }

class APIError extends Error {
  code?: string
  constructor(message: string, code?: string) { super(message); this.code = code }
}

const setup = ref<SetupStatus | null>(null)
const admin = ref<Admin | null>(null)
const clients = ref<Client[]>([])
const newDevice = ref({ name: '', fingerprint: '' })
const selectedProfile = ref<{ client_id: string; uri: string; json: unknown } | null>(null)
const error = ref('')
const busy = ref(false)
const language = ref<'en' | 'ru'>(navigator.language.toLowerCase().startsWith('ru') ? 'ru' : 'en')
const setupForm = ref({ username: 'admin', password: '', publicHost: '', publicPort: 443, realityTarget: 'www.cloudflare.com:443', realitySNI: 'www.cloudflare.com' })
const loginForm = ref({ username: 'admin', password: '', totpCode: '', recoveryCode: '' })
const totpStatus = ref<TOTPStatus | null>(null)
const totpSetup = ref<TOTPSetup | null>(null)
const totpConfirmCode = ref('')
const disableTOTPForm = ref({ password: '', code: '' })
const loginNeedsTOTP = ref(false)
const loginUsesRecovery = ref(false)
let events: EventSource | null = null

const text = {
  en: {
    title: 'Xray-easy', setup: 'Initial setup', login: 'Administrator login', username: 'Username', password: 'Password', host: 'Public host or IPv4', port: 'Public port (from Compose)', target: 'REALITY target', sni: 'REALITY SNI', create: 'Create administrator', signIn: 'Sign in', ready: 'Devices', newDevice: 'Device name', fingerprint: 'Fingerprint', createDevice: 'Create device', profile: 'Profile', qr: 'QR code', download: 'Download JSON', enabled: 'enabled', disabled: 'disabled', revoked: 'revoked', online: 'online', offline: 'offline', traffic: 'traffic', enable: 'Enable', disable: 'Disable', revoke: 'Revoke', logout: 'Sign out', logoutAll: 'Sign out all sessions', language: 'Русский', security: 'Account security', totp: 'Two-factor authentication (TOTP)', totpEnabled: 'TOTP is enabled', totpDisabled: 'TOTP is not enabled', enableTOTP: 'Enable TOTP', setupTOTP: 'Scan this URI or enter the secret in your authenticator, then enter a code', secret: 'Secret', confirmTOTP: 'Confirm TOTP', recovery: 'Save these recovery codes. Each can be used once.', recoveryLeft: 'recovery codes remaining', disableTOTP: 'Disable TOTP', disableTOTPHint: 'Enter your password and a current TOTP code', loginCode: 'TOTP code', recoveryCode: 'Recovery code', useRecovery: 'Use a recovery code', useTOTP: 'Use a TOTP code',
  },
  ru: {
    title: 'Xray-easy', setup: 'Первичная настройка', login: 'Вход администратора', username: 'Имя пользователя', password: 'Пароль', host: 'Публичный адрес или IPv4', port: 'Публичный порт (из Compose)', target: 'REALITY target', sni: 'REALITY SNI', create: 'Создать администратора', signIn: 'Войти', ready: 'Устройства', newDevice: 'Имя устройства', fingerprint: 'Fingerprint', createDevice: 'Создать устройство', profile: 'Профиль', qr: 'QR-код', download: 'Скачать JSON', enabled: 'включено', disabled: 'выключено', revoked: 'отозвано', online: 'онлайн', offline: 'не в сети', traffic: 'трафик', enable: 'Включить', disable: 'Выключить', revoke: 'Отозвать', logout: 'Выйти', logoutAll: 'Выйти со всех сессий', language: 'English', security: 'Безопасность аккаунта', totp: 'Двухфакторная аутентификация (TOTP)', totpEnabled: 'TOTP включён', totpDisabled: 'TOTP не включён', enableTOTP: 'Включить TOTP', setupTOTP: 'Отсканируйте URI или введите секрет в приложении-аутентификаторе, затем введите код', secret: 'Секрет', confirmTOTP: 'Подтвердить TOTP', recovery: 'Сохраните recovery-коды. Каждый используется один раз.', recoveryLeft: 'recovery-кодов осталось', disableTOTP: 'Отключить TOTP', disableTOTPHint: 'Введите пароль и текущий код TOTP', loginCode: 'Код TOTP', recoveryCode: 'Recovery-код', useRecovery: 'Использовать recovery-код', useTOTP: 'Использовать код TOTP',
  },
}

const t = () => text[language.value]

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(url, { headers: { 'Content-Type': 'application/json' }, ...options })
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) throw new APIError(payload.error || `HTTP ${response.status}`, payload.code)
  return payload as T
}

function showError(cause: unknown) { error.value = cause instanceof Error ? cause.message : 'Request failed' }

async function load() {
  error.value = ''
  try {
    setup.value = await request<SetupStatus>('/api/setup/status')
    if (setup.value.public_port) setupForm.value.publicPort = setup.value.public_port
    if (setup.value.initialized) {
      try { admin.value = await request<Admin>('/api/me') } catch { admin.value = null }
      if (admin.value) { await loadAuthenticated(); connectEvents() }
    }
  } catch (cause) { showError(cause) }
}

async function loadAuthenticated() { await Promise.all([loadClients(), loadTOTPStatus()]) }
async function loadClients() { clients.value = await request<Client[]>('/api/clients') }
async function loadTOTPStatus() { totpStatus.value = await request<TOTPStatus>('/api/auth/totp/status') }

function connectEvents() {
  if (events || !admin.value) return
  events = new EventSource('/api/events')
  events.addEventListener('stats', () => { if (admin.value) void loadClients() })
  events.onerror = () => { events?.close(); events = null; if (admin.value) window.setTimeout(connectEvents, 3000) }
}

async function initialize() {
  busy.value = true; error.value = ''
  try {
    await request('/api/setup/initialize', { method: 'POST', body: JSON.stringify({ username: setupForm.value.username, password: setupForm.value.password, public_host: setupForm.value.publicHost, public_port: setupForm.value.publicPort, reality_target: setupForm.value.realityTarget, reality_sni: setupForm.value.realitySNI }) })
    loginForm.value.username = setupForm.value.username; setup.value = { initialized: true }
  } catch (cause) { showError(cause) } finally { busy.value = false }
}

async function login() {
  busy.value = true; error.value = ''
  try { admin.value = await request<Admin>('/api/auth/login', { method: 'POST', body: JSON.stringify({ username: loginForm.value.username, password: loginForm.value.password }) }); loginNeedsTOTP.value = false; await loadAuthenticated(); connectEvents() }
  catch (cause) { if (cause instanceof APIError && cause.code === 'totp_required') loginNeedsTOTP.value = true; else showError(cause) }
  finally { busy.value = false }
}

async function loginTOTP() {
  busy.value = true; error.value = ''
  try { admin.value = await request<Admin>('/api/auth/login/totp', { method: 'POST', body: JSON.stringify({ username: loginForm.value.username, password: loginForm.value.password, totp_code: loginForm.value.totpCode }) }); loginNeedsTOTP.value = false; await loadAuthenticated(); connectEvents() }
  catch (cause) { showError(cause) } finally { busy.value = false }
}

async function loginRecovery() {
  busy.value = true; error.value = ''
  try { admin.value = await request<Admin>('/api/auth/login/recovery', { method: 'POST', body: JSON.stringify({ username: loginForm.value.username, password: loginForm.value.password, recovery_code: loginForm.value.recoveryCode }) }); loginNeedsTOTP.value = false; await loadAuthenticated(); connectEvents() }
  catch (cause) { showError(cause) } finally { busy.value = false }
}

async function logout() { await request('/api/auth/logout', { method: 'POST' }); events?.close(); events = null; admin.value = null; totpStatus.value = null }

async function logoutAll() {
  busy.value = true; error.value = ''
  try { await request('/api/auth/logout-all', { method: 'POST' }); events?.close(); events = null; admin.value = null; totpStatus.value = null }
  catch (cause) { showError(cause) } finally { busy.value = false }
}

async function startTOTPSetup() {
  busy.value = true; error.value = ''
  try { totpSetup.value = await request<TOTPSetup>('/api/auth/totp/setup', { method: 'POST' }) }
  catch (cause) { showError(cause) } finally { busy.value = false }
}

async function confirmTOTP() {
  if (!totpSetup.value) return
  busy.value = true; error.value = ''
  try { await request('/api/auth/totp/enable', { method: 'POST', body: JSON.stringify({ setup_token: totpSetup.value.setup_token, code: totpConfirmCode.value }) }); totpSetup.value = null; totpConfirmCode.value = ''; await loadTOTPStatus() }
  catch (cause) { showError(cause) } finally { busy.value = false }
}

async function disableTOTP() {
  busy.value = true; error.value = ''
  try { await request('/api/auth/totp/disable', { method: 'POST', body: JSON.stringify(disableTOTPForm.value) }); admin.value = null; totpStatus.value = null; disableTOTPForm.value = { password: '', code: '' }; events?.close(); events = null }
  catch (cause) { showError(cause) } finally { busy.value = false }
}

async function createDevice() {
  busy.value = true; error.value = ''
  try { const created = await request<Client>('/api/clients', { method: 'POST', body: JSON.stringify({ name: newDevice.value.name, fingerprint: newDevice.value.fingerprint || undefined }) }); clients.value.push(created); newDevice.value = { name: '', fingerprint: '' }; await showProfile(created) }
  catch (cause) { showError(cause) } finally { busy.value = false }
}

async function showProfile(client: Client) { selectedProfile.value = await request<{ client_id: string; uri: string; json: unknown }>(`/api/clients/${client.id}/profile?format=uri`) }

async function changeState(client: Client, action: 'enable' | 'disable' | 'revoke') {
  busy.value = true; error.value = ''
  try { const updated = await request<Client>(`/api/clients/${client.id}/${action}`, { method: 'POST' }); const index = clients.value.findIndex(item => item.id === client.id); if (index >= 0) clients.value[index] = updated }
  catch (cause) { showError(cause) } finally { busy.value = false }
}

onMounted(load)
onBeforeUnmount(() => events?.close())

function formatBytes(value: number) { if (!value) return '0 B'; const units = ['B', 'KB', 'MB', 'GB', 'TB']; let amount = value; let unit = 0; while (amount >= 1024 && unit < units.length - 1) { amount /= 1024; unit += 1 }; return `${amount.toFixed(amount >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}` }
function formatLastSeen(value?: string) { if (!value) return ''; return new Date(value).toLocaleString(language.value === 'ru' ? 'ru-RU' : 'en-US') }
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
      <template v-if="loginNeedsTOTP">
        <label v-if="!loginUsesRecovery">{{ t().loginCode }}<input v-model="loginForm.totpCode" inputmode="numeric" autocomplete="one-time-code" /></label>
        <label v-else>{{ t().recoveryCode }}<input v-model="loginForm.recoveryCode" autocomplete="one-time-code" /></label>
        <button :disabled="busy" @click="loginUsesRecovery ? loginRecovery() : loginTOTP()">{{ t().signIn }}</button>
        <button class="secondary" @click="loginUsesRecovery = !loginUsesRecovery">{{ loginUsesRecovery ? t().useTOTP : t().useRecovery }}</button>
      </template>
      <button v-else :disabled="busy" @click="login">{{ t().signIn }}</button>
    </section>
    <section class="card" v-else>
      <div class="card-title"><h1>{{ t().ready }}</h1><span><button class="secondary" @click="logoutAll">{{ t().logoutAll }}</button><button class="secondary" @click="logout">{{ t().logout }}</button></span></div>
      <div class="device-create"><input v-model="newDevice.name" :placeholder="t().newDevice" @keyup.enter="createDevice" /><select v-model="newDevice.fingerprint"><option value="">chrome</option><option value="safari">safari</option><option value="ios">ios</option><option value="firefox">firefox</option><option value="edge">edge</option></select><button :disabled="busy || !newDevice.name" @click="createDevice">{{ t().createDevice }}</button></div>
      <ul class="devices"><li v-for="client in clients" :key="client.id"><span><strong>{{ client.name }}</strong><small>{{ client.revoked ? t().revoked : client.enabled ? t().enabled : t().disabled }} · {{ client.online ? t().online : t().offline }} · {{ t().traffic }} ↑{{ formatBytes(client.upload_bytes) }} ↓{{ formatBytes(client.download_bytes) }}<template v-if="client.last_seen"> · {{ formatLastSeen(client.last_seen) }}</template></small></span><span><button class="secondary" @click="showProfile(client)">{{ t().profile }}</button><button v-if="!client.revoked && !client.enabled" class="secondary" @click="changeState(client, 'enable')">{{ t().enable }}</button><button v-if="!client.revoked && client.enabled" class="secondary" @click="changeState(client, 'disable')">{{ t().disable }}</button><button v-if="!client.revoked" class="danger" @click="changeState(client, 'revoke')">{{ t().revoke }}</button></span></li></ul>
      <div v-if="selectedProfile" class="profile"><label>VLESS URI<textarea readonly :value="selectedProfile.uri"></textarea></label><img :src="`/api/clients/${selectedProfile.client_id}/profile?format=qr`" :alt="t().qr" /><a :href="`/api/clients/${selectedProfile.client_id}/profile?format=json`">{{ t().download }}</a></div>
      <section class="security">
        <h2>{{ t().security }}</h2>
        <p>{{ t().totp }}: <strong>{{ totpStatus?.enabled ? t().totpEnabled : t().totpDisabled }}</strong></p>
        <template v-if="!totpStatus?.enabled && !totpSetup"><button :disabled="busy" @click="startTOTPSetup">{{ t().enableTOTP }}</button></template>
        <template v-if="totpSetup">
          <p>{{ t().setupTOTP }}</p><label>{{ t().secret }}<input readonly :value="totpSetup.secret" /></label><label>otpauth URI<textarea readonly :value="totpSetup.otpauth_uri"></textarea></label>
          <p><strong>{{ t().recovery }}</strong></p><pre class="recovery-codes">{{ totpSetup.recovery_codes.join('\n') }}</pre>
          <label>{{ t().loginCode }}<input v-model="totpConfirmCode" inputmode="numeric" autocomplete="one-time-code" /></label><button :disabled="busy || !totpConfirmCode" @click="confirmTOTP">{{ t().confirmTOTP }}</button>
        </template>
        <template v-if="totpStatus?.enabled">
          <p>{{ totpStatus.recovery_codes_remaining }} {{ t().recoveryLeft }}</p><p>{{ t().disableTOTPHint }}</p><label>{{ t().password }}<input v-model="disableTOTPForm.password" type="password" autocomplete="current-password" /></label><label>{{ t().loginCode }}<input v-model="disableTOTPForm.code" inputmode="numeric" autocomplete="one-time-code" /></label><button class="danger" :disabled="busy" @click="disableTOTP">{{ t().disableTOTP }}</button>
        </template>
      </section>
    </section>
  </main>
</template>

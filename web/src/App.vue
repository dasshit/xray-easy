<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'

type SetupStatus = { initialized: boolean; public_port?: number }
type Admin = { username: string; totp_enabled?: boolean; recovery_codes_remaining?: number }
type Client = { id: string; name: string; enabled: boolean; revoked: boolean; fingerprint?: string; online: boolean; last_seen?: string; upload_bytes: number; download_bytes: number }
type TOTPStatus = { enabled: boolean; recovery_codes_remaining: number }
type TOTPSetup = { setup_token: string; secret: string; otpauth_uri: string; recovery_codes: string[]; expires_in: number }
type Settings = { public_host: string; public_port: number; reality_target: string; reality_sni: string; client_fingerprint: string; protocol: string; network: string; security: string; flow: string }
type SettingsDiff = { field: string; from: string; to: string }
type SettingsChange = { change_id: string; expires_in: number; expected_confirmation: string; requires_confirmation: boolean; diff: SettingsDiff[]; consequences: string[]; revoked_clients: number; settings: Settings; confirmation: string }
type NodeStatus = { state: string; restart_count: number; last_error?: string; last_exit?: string; stats_last_error?: string; supervisor_error?: string }
type DiagnosticEntry = { at: string; component: string; level: string; message: string }
type Section = 'profiles' | 'settings' | 'diagnostics' | 'security'
type ClientAction = { client: Client; action: 'enable' | 'disable' | 'revoke' } | null
type Theme = 'light' | 'dark'

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
const theme = ref<Theme>(initialTheme())
const activeSection = ref<Section>('profiles')
const createModalOpen = ref(false)
const clientAction = ref<ClientAction>(null)
const setupForm = ref({ username: 'admin', password: '', publicHost: '', publicPort: 443, realityTarget: 'www.cloudflare.com:443', realitySNI: 'www.cloudflare.com' })
const loginForm = ref({ username: 'admin', password: '', totpCode: '', recoveryCode: '' })
const totpStatus = ref<TOTPStatus | null>(null)
const totpSetup = ref<TOTPSetup | null>(null)
const totpConfirmCode = ref('')
const disableTOTPForm = ref({ password: '', code: '' })
const lastBackup = ref('')
const settings = ref<Settings | null>(null)
const settingsForm = ref({ publicHost: '', realityTarget: '', realitySNI: '', clientFingerprint: 'chrome', rotatePrivateKey: false })
const pendingSettings = ref<SettingsChange | null>(null)
const nodeStatus = ref<NodeStatus | null>(null)
const diagnostics = ref<DiagnosticEntry[]>([])
const loginNeedsTOTP = ref(false)
const loginUsesRecovery = ref(false)
let events: EventSource | null = null

const text = {
  en: {
    title: 'Xray-easy', setup: 'Initial setup', login: 'Administrator login', username: 'Username', password: 'Password', host: 'Public host or IPv4', port: 'Public port (from Compose)', target: 'REALITY target', sni: 'REALITY SNI', create: 'Create administrator', signIn: 'Sign in',
    profiles: 'Profiles', profile: 'Profile', createProfile: 'Create profile', newDevice: 'Device name', fingerprint: 'Fingerprint', createDevice: 'Create profile', emptyProfiles: 'No profiles yet. Create the first profile for a device.',
    qr: 'QR code', download: 'Download JSON', copyUri: 'VLESS URI', enabled: 'enabled', disabled: 'disabled', revoked: 'revoked', online: 'online', offline: 'offline', traffic: 'traffic', enable: 'Enable', disable: 'Disable', remove: 'Delete profile', close: 'Close', cancel: 'Cancel', confirm: 'Confirm', action: 'Confirm action', enableConfirm: 'Enable this profile?', disableConfirm: 'Disable this profile? The device will stop connecting until it is enabled again.', removeConfirm: 'Delete this profile? Its credentials will be revoked permanently.', noUndo: 'Revocation cannot be undone.',
    logout: 'Sign out', logoutAll: 'Sign out all sessions', language: 'Русский', settings: 'Settings', saveSettings: 'Review changes', applySettings: 'Apply settings', rotateKey: 'Generate a new REALITY key', confirmation: 'Confirmation', settingsWarning: 'Existing device profiles may stop working and will be revoked.', expected: 'Type exactly', settingsDiff: 'Changes', consequences: 'Consequences', revokedClients: 'Profiles to revoke',
    diagnostics: 'Diagnostics', xrayState: 'Xray state', restarts: 'Restarts', refreshDiagnostics: 'Refresh diagnostics', noDiagnostics: 'No warnings or errors', useLightTheme: 'Light theme', useDarkTheme: 'Dark theme',
    security: 'Security', backup: 'Create backup', backupCreated: 'Backup created', totp: 'Two-factor authentication (TOTP)', totpEnabled: 'TOTP is enabled', totpDisabled: 'TOTP is not enabled', enableTOTP: 'Enable TOTP', setupTOTP: 'Scan this URI or enter the secret in your authenticator, then enter a code', secret: 'Secret', confirmTOTP: 'Confirm TOTP', recovery: 'Save these recovery codes. Each can be used once.', recoveryLeft: 'recovery codes remaining', disableTOTP: 'Disable TOTP', disableTOTPHint: 'Enter your password and a current TOTP code', loginCode: 'TOTP code', recoveryCode: 'Recovery code', useRecovery: 'Use a recovery code', useTOTP: 'Use a TOTP code',
  },
  ru: {
    title: 'Xray-easy', setup: 'Первичная настройка', login: 'Вход администратора', username: 'Имя пользователя', password: 'Пароль', host: 'Публичный адрес или IPv4', port: 'Публичный порт (из Compose)', target: 'REALITY target', sni: 'REALITY SNI', create: 'Создать администратора', signIn: 'Войти',
    profiles: 'Профили', profile: 'Профиль', createProfile: 'Создать профиль', newDevice: 'Имя устройства', fingerprint: 'Fingerprint', createDevice: 'Создать профиль', emptyProfiles: 'Профилей пока нет. Создайте первый профиль для устройства.',
    qr: 'QR-код', download: 'Скачать JSON', copyUri: 'VLESS URI', enabled: 'включён', disabled: 'выключен', revoked: 'отозван', online: 'онлайн', offline: 'не в сети', traffic: 'трафик', enable: 'Включить', disable: 'Выключить', remove: 'Удалить профиль', close: 'Закрыть', cancel: 'Отмена', confirm: 'Подтвердить', action: 'Подтверждение действия', enableConfirm: 'Включить профиль?', disableConfirm: 'Выключить профиль? Устройство перестанет подключаться, пока профиль не будет включён снова.', removeConfirm: 'Удалить профиль? Его учётные данные будут отозваны навсегда.', noUndo: 'Отзыв нельзя отменить.',
    logout: 'Выйти', logoutAll: 'Выйти со всех сессий', language: 'English', settings: 'Настройки', saveSettings: 'Проверить изменения', applySettings: 'Применить настройки', rotateKey: 'Сгенерировать новый REALITY-ключ', confirmation: 'Подтверждение', settingsWarning: 'Старые профили могут перестать работать и будут отозваны.', expected: 'Введите точно', settingsDiff: 'Изменения', consequences: 'Последствия', revokedClients: 'Профилей будет отозвано',
    diagnostics: 'Диагностика', xrayState: 'Состояние Xray', restarts: 'Перезапуски', refreshDiagnostics: 'Обновить диагностику', noDiagnostics: 'Предупреждений и ошибок нет', useLightTheme: 'Светлая тема', useDarkTheme: 'Тёмная тема',
    security: 'Безопасность', backup: 'Создать backup', backupCreated: 'Backup создан', totp: 'Двухфакторная аутентификация (TOTP)', totpEnabled: 'TOTP включён', totpDisabled: 'TOTP не включён', enableTOTP: 'Включить TOTP', setupTOTP: 'Отсканируйте URI или введите секрет в приложении-аутентификаторе, затем введите код', secret: 'Секрет', confirmTOTP: 'Подтвердить TOTP', recovery: 'Сохраните recovery-коды. Каждый используется один раз.', recoveryLeft: 'recovery-кодов осталось', disableTOTP: 'Отключить TOTP', disableTOTPHint: 'Введите пароль и текущий код TOTP', loginCode: 'Код TOTP', recoveryCode: 'Recovery-код', useRecovery: 'Использовать recovery-код', useTOTP: 'Использовать код TOTP',
  },
}

const t = () => text[language.value]

function initialTheme(): Theme {
  if (typeof window === 'undefined') return 'light'
  const stored = window.localStorage.getItem('xray-easy-theme')
  if (stored === 'light' || stored === 'dark') return stored
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

function applyTheme(next: Theme) {
  theme.value = next
  document.documentElement.dataset.theme = next
  window.localStorage.setItem('xray-easy-theme', next)
}

function toggleTheme() { applyTheme(theme.value === 'dark' ? 'light' : 'dark') }

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
async function loadAuthenticated() { await Promise.all([loadClients(), loadTOTPStatus(), loadSettings(), loadStatus(), loadDiagnostics()]) }
async function loadClients() { clients.value = await request<Client[]>('/api/clients') }
async function loadTOTPStatus() { totpStatus.value = await request<TOTPStatus>('/api/auth/totp/status') }
async function loadStatus() { try { nodeStatus.value = await request<NodeStatus>('/api/status') } catch { nodeStatus.value = { state: 'unavailable', restart_count: 0 } } }
async function loadDiagnostics() {
  const results = await Promise.allSettled([request<{ entries: DiagnosticEntry[] }>('/api/logs?component=xray&limit=100'), request<{ entries: DiagnosticEntry[] }>('/api/logs?component=app&limit=100')])
  diagnostics.value = results.flatMap(result => result.status === 'fulfilled' ? result.value.entries : []).sort((left, right) => left.at.localeCompare(right.at)).slice(-100)
}
async function loadSettings() {
  settings.value = await request<Settings>('/api/settings')
  settingsForm.value = { publicHost: settings.value.public_host, realityTarget: settings.value.reality_target, realitySNI: settings.value.reality_sni, clientFingerprint: settings.value.client_fingerprint, rotatePrivateKey: false }
}
function connectEvents() {
  if (events || !admin.value) return
  events = new EventSource('/api/events')
  events.addEventListener('stats', () => { if (admin.value) void loadClients() })
  events.addEventListener('status', () => { if (admin.value) { void loadStatus(); void loadDiagnostics() } })
  events.onerror = () => { events?.close(); events = null; if (admin.value) window.setTimeout(connectEvents, 3000) }
}

async function initialize() {
  busy.value = true; error.value = ''
  try { await request('/api/setup/initialize', { method: 'POST', body: JSON.stringify({ username: setupForm.value.username, password: setupForm.value.password, public_host: setupForm.value.publicHost, public_port: setupForm.value.publicPort, reality_target: setupForm.value.realityTarget, reality_sni: setupForm.value.realitySNI }) }); loginForm.value.username = setupForm.value.username; setup.value = { initialized: true } }
  catch (cause) { showError(cause) } finally { busy.value = false }
}
async function login() {
  busy.value = true; error.value = ''
  try { admin.value = await request<Admin>('/api/auth/login', { method: 'POST', body: JSON.stringify({ username: loginForm.value.username, password: loginForm.value.password }) }); loginNeedsTOTP.value = false; await loadAuthenticated(); connectEvents() }
  catch (cause) { if (cause instanceof APIError && cause.code === 'totp_required') loginNeedsTOTP.value = true; else showError(cause) } finally { busy.value = false }
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
async function logoutAll() { busy.value = true; error.value = ''; try { await request('/api/auth/logout-all', { method: 'POST' }); events?.close(); events = null; admin.value = null; totpStatus.value = null } catch (cause) { showError(cause) } finally { busy.value = false } }

function openCreateModal() { error.value = ''; newDevice.value = { name: '', fingerprint: '' }; createModalOpen.value = true }
function closeCreateModal() { if (!busy.value) createModalOpen.value = false }
async function createDevice() {
  busy.value = true; error.value = ''
  try { const created = await request<Client>('/api/clients', { method: 'POST', body: JSON.stringify({ name: newDevice.value.name, fingerprint: newDevice.value.fingerprint || undefined }) }); clients.value.push(created); createModalOpen.value = false; await showProfile(created) }
  catch (cause) { showError(cause) } finally { busy.value = false }
}
async function showProfile(client: Client) { try { selectedProfile.value = await request<{ client_id: string; uri: string; json: unknown }>(`/api/clients/${client.id}/profile?format=uri`) } catch (cause) { showError(cause) } }
function closeProfile() { if (!busy.value) selectedProfile.value = null }
function openClientAction(client: Client, action: 'enable' | 'disable' | 'revoke') { error.value = ''; clientAction.value = { client, action } }
function closeClientAction() { if (!busy.value) clientAction.value = null }
async function confirmClientAction() {
  if (!clientAction.value) return
  const { client, action } = clientAction.value
  busy.value = true; error.value = ''
  try { const updated = await request<Client>(`/api/clients/${client.id}/${action}`, { method: 'POST' }); const index = clients.value.findIndex(item => item.id === client.id); if (index >= 0) clients.value[index] = updated; clientAction.value = null }
  catch (cause) { showError(cause) } finally { busy.value = false }
}

async function createBackup() { busy.value = true; error.value = ''; try { const result = await request<{ name: string }>('/api/backups', { method: 'POST' }); lastBackup.value = result.name } catch (cause) { showError(cause) } finally { busy.value = false } }
async function reviewSettings() {
  busy.value = true; error.value = ''; pendingSettings.value = null
  try { const result = await request<Omit<SettingsChange, 'confirmation'>>('/api/settings', { method: 'PATCH', body: JSON.stringify({ public_host: settingsForm.value.publicHost, reality_target: settingsForm.value.realityTarget, reality_sni: settingsForm.value.realitySNI, client_fingerprint: settingsForm.value.clientFingerprint, rotate_private_key: settingsForm.value.rotatePrivateKey }) }); pendingSettings.value = { ...result, confirmation: '' } }
  catch (cause) { showError(cause) } finally { busy.value = false }
}
async function applySettings() {
  if (!pendingSettings.value) return
  busy.value = true; error.value = ''
  try { await request('/api/settings/apply', { method: 'POST', body: JSON.stringify({ change_id: pendingSettings.value.change_id, confirmation: pendingSettings.value.confirmation }) }); pendingSettings.value = null; await loadSettings(); await loadClients() }
  catch (cause) { showError(cause) } finally { busy.value = false }
}
async function startTOTPSetup() { busy.value = true; error.value = ''; try { totpSetup.value = await request<TOTPSetup>('/api/auth/totp/setup', { method: 'POST' }) } catch (cause) { showError(cause) } finally { busy.value = false } }
async function confirmTOTP() {
  if (!totpSetup.value) return
  busy.value = true; error.value = ''
  try { await request('/api/auth/totp/enable', { method: 'POST', body: JSON.stringify({ setup_token: totpSetup.value.setup_token, code: totpConfirmCode.value }) }); totpSetup.value = null; totpConfirmCode.value = ''; await loadTOTPStatus() }
  catch (cause) { showError(cause) } finally { busy.value = false }
}
async function disableTOTP() { busy.value = true; error.value = ''; try { await request('/api/auth/totp/disable', { method: 'POST', body: JSON.stringify(disableTOTPForm.value) }); admin.value = null; totpStatus.value = null; disableTOTPForm.value = { password: '', code: '' }; events?.close(); events = null } catch (cause) { showError(cause) } finally { busy.value = false } }

onMounted(() => { applyTheme(theme.value); void load() })
onBeforeUnmount(() => events?.close())
function formatBytes(value: number) { if (!value) return '0 B'; const units = ['B', 'KB', 'MB', 'GB', 'TB']; let amount = value; let unit = 0; while (amount >= 1024 && unit < units.length - 1) { amount /= 1024; unit += 1 }; return `${amount.toFixed(amount >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}` }
function formatLastSeen(value?: string) { if (!value) return ''; return new Date(value).toLocaleString(language.value === 'ru' ? 'ru-RU' : 'en-US') }
function actionTitle(action?: ClientAction['action']) { if (action === 'enable') return t().enableConfirm; if (action === 'disable') return t().disableConfirm; return t().removeConfirm }
function actionLabel(action?: ClientAction['action']) { if (action === 'enable') return t().enable; if (action === 'disable') return t().disable; return t().remove }
</script>

<template>
  <main class="shell">
    <header class="topbar"><strong>{{ t().title }}</strong><div class="topbar-actions"><button class="theme-toggle" :aria-label="theme === 'dark' ? t().useLightTheme : t().useDarkTheme" @click="toggleTheme">{{ theme === 'dark' ? '☀' : '☾' }}<span>{{ theme === 'dark' ? t().useLightTheme : t().useDarkTheme }}</span></button><button class="language" @click="language = language === 'en' ? 'ru' : 'en'">{{ t().language }}</button></div></header>
    <section class="card error-card" v-if="error"><p class="error">{{ error }}</p></section>
    <section class="card auth-card" v-if="!setup?.initialized">
      <h1>{{ t().setup }}</h1><label>{{ t().username }}<input v-model="setupForm.username" autocomplete="username" /></label><label>{{ t().password }}<input v-model="setupForm.password" type="password" autocomplete="new-password" /></label><label>{{ t().host }}<input v-model="setupForm.publicHost" placeholder="vpn.example.com" /></label><label>{{ t().port }}<input v-model.number="setupForm.publicPort" type="number" readonly /></label><label>{{ t().target }}<input v-model="setupForm.realityTarget" placeholder="www.cloudflare.com:443" /></label><label>{{ t().sni }}<input v-model="setupForm.realitySNI" placeholder="www.cloudflare.com" /></label><button :disabled="busy" @click="initialize">{{ t().create }}</button>
    </section>
    <section class="card auth-card" v-else-if="!admin">
      <h1>{{ t().login }}</h1><label>{{ t().username }}<input v-model="loginForm.username" autocomplete="username" /></label><label>{{ t().password }}<input v-model="loginForm.password" type="password" autocomplete="current-password" /></label><template v-if="loginNeedsTOTP"><label v-if="!loginUsesRecovery">{{ t().loginCode }}<input v-model="loginForm.totpCode" inputmode="numeric" autocomplete="one-time-code" /></label><label v-else>{{ t().recoveryCode }}<input v-model="loginForm.recoveryCode" autocomplete="one-time-code" /></label><button :disabled="busy" @click="loginUsesRecovery ? loginRecovery() : loginTOTP()">{{ t().signIn }}</button><button class="secondary" @click="loginUsesRecovery = !loginUsesRecovery">{{ loginUsesRecovery ? t().useTOTP : t().useRecovery }}</button></template><button v-else :disabled="busy" @click="login">{{ t().signIn }}</button>
    </section>
    <section class="card dashboard" v-else>
      <div class="dashboard-header"><div><p class="eyebrow">{{ t().title }}</p><h1>{{ t().profiles }}</h1></div><div class="header-actions"><button class="secondary" @click="logoutAll">{{ t().logoutAll }}</button><button class="secondary" @click="logout">{{ t().logout }}</button></div></div>
      <nav class="tabs" :aria-label="t().title"><button :class="{ active: activeSection === 'profiles' }" @click="activeSection = 'profiles'">{{ t().profiles }}</button><button :class="{ active: activeSection === 'settings' }" @click="activeSection = 'settings'">{{ t().settings }}</button><button :class="{ active: activeSection === 'diagnostics' }" @click="activeSection = 'diagnostics'">{{ t().diagnostics }}</button><button :class="{ active: activeSection === 'security' }" @click="activeSection = 'security'">{{ t().security }}</button></nav>
      <section v-if="activeSection === 'profiles'" class="section-panel"><div class="section-heading"><div><h2>{{ t().profiles }}</h2><p class="muted">{{ t().traffic }} · {{ clients.length }}</p></div><button @click="openCreateModal">{{ t().createProfile }}</button></div><p v-if="!clients.length" class="empty-state">{{ t().emptyProfiles }}</p><ul v-else class="devices"><li v-for="client in clients" :key="client.id" class="device-row"><div class="device-main"><strong>{{ client.name }}</strong><span class="device-meta"><span class="status-dot" :class="{ online: client.online }"></span>{{ client.revoked ? t().revoked : client.enabled ? t().enabled : t().disabled }} · {{ client.online ? t().online : t().offline }} · {{ t().traffic }} ↑{{ formatBytes(client.upload_bytes) }} ↓{{ formatBytes(client.download_bytes) }}<template v-if="client.last_seen"> · {{ formatLastSeen(client.last_seen) }}</template></span></div><div class="device-actions"><button v-if="!client.revoked" class="secondary" @click="showProfile(client)">{{ t().profile }}</button><button v-if="!client.revoked" class="secondary" @click="openClientAction(client, client.enabled ? 'disable' : 'enable')">{{ client.enabled ? t().disable : t().enable }}</button><button v-if="!client.revoked" class="danger" @click="openClientAction(client, 'revoke')">{{ t().remove }}</button></div></li></ul></section>
      <section v-if="activeSection === 'settings' && settings" class="section-panel"><div class="section-heading"><div><h2>{{ t().settings }}</h2><p class="muted">{{ settings.protocol.toUpperCase() }} · {{ settings.security.toUpperCase() }} · {{ settings.flow }}</p></div></div><label>{{ t().host }}<input v-model="settingsForm.publicHost" /></label><label>{{ t().target }}<input v-model="settingsForm.realityTarget" /></label><label>{{ t().sni }}<input v-model="settingsForm.realitySNI" /></label><label>{{ t().fingerprint }}<select v-model="settingsForm.clientFingerprint"><option value="chrome">chrome</option><option value="safari">safari</option><option value="ios">ios</option><option value="firefox">firefox</option><option value="edge">edge</option><option value="android">android</option><option value="random">random</option></select></label><label class="checkbox"><input v-model="settingsForm.rotatePrivateKey" type="checkbox" /> {{ t().rotateKey }}</label><p class="hint">{{ t().settingsWarning }}</p><button :disabled="busy" @click="reviewSettings">{{ t().saveSettings }}</button></section>
      <section v-if="activeSection === 'diagnostics'" class="section-panel"><div class="section-heading"><div><h2>{{ t().diagnostics }}</h2><p class="muted">{{ t().xrayState }}: <strong>{{ nodeStatus?.state || 'unknown' }}</strong> · {{ t().restarts }}: {{ nodeStatus?.restart_count || 0 }}</p></div><button class="secondary" :disabled="busy" @click="loadStatus(); loadDiagnostics()">{{ t().refreshDiagnostics }}</button></div><p v-if="nodeStatus?.last_error" class="error">{{ nodeStatus.last_error }}</p><p v-if="nodeStatus?.stats_last_error" class="error">{{ nodeStatus.stats_last_error }}</p><ul v-if="diagnostics.length" class="diagnostics-list"><li v-for="entry in diagnostics" :key="`${entry.at}-${entry.component}-${entry.message}`"><small>{{ formatLastSeen(entry.at) }} · {{ entry.component }} · {{ entry.level }}</small><span>{{ entry.message }}</span></li></ul><p v-else class="hint">{{ t().noDiagnostics }}</p></section>
      <section v-if="activeSection === 'security'" class="section-panel security-panel"><div class="section-heading"><div><h2>{{ t().security }}</h2><p class="muted">{{ t().totp }}: <strong>{{ totpStatus?.enabled ? t().totpEnabled : t().totpDisabled }}</strong></p></div><button class="secondary" :disabled="busy" @click="createBackup">{{ t().backup }}</button></div><p v-if="lastBackup" class="backup-name">{{ t().backupCreated }}: {{ lastBackup }}</p><template v-if="!totpStatus?.enabled && !totpSetup"><button :disabled="busy" @click="startTOTPSetup">{{ t().enableTOTP }}</button></template><template v-if="totpSetup"><p>{{ t().setupTOTP }}</p><label>{{ t().secret }}<input readonly :value="totpSetup.secret" /></label><label>otpauth URI<textarea readonly :value="totpSetup.otpauth_uri"></textarea></label><p><strong>{{ t().recovery }}</strong></p><pre class="recovery-codes">{{ totpSetup.recovery_codes.join('\n') }}</pre><label>{{ t().loginCode }}<input v-model="totpConfirmCode" inputmode="numeric" autocomplete="one-time-code" /></label><button :disabled="busy || !totpConfirmCode" @click="confirmTOTP">{{ t().confirmTOTP }}</button></template><template v-if="totpStatus?.enabled"><p>{{ totpStatus.recovery_codes_remaining }} {{ t().recoveryLeft }}</p><p>{{ t().disableTOTPHint }}</p><label>{{ t().password }}<input v-model="disableTOTPForm.password" type="password" autocomplete="current-password" /></label><label>{{ t().loginCode }}<input v-model="disableTOTPForm.code" inputmode="numeric" autocomplete="one-time-code" /></label><button class="danger" :disabled="busy" @click="disableTOTP">{{ t().disableTOTP }}</button></template></section>

      <div v-if="createModalOpen" class="modal-backdrop" @click.self="closeCreateModal"><div class="modal" role="dialog" aria-modal="true"><div class="modal-header"><div><p class="eyebrow">{{ t().profiles }}</p><h2>{{ t().createProfile }}</h2></div><button class="icon-button" :aria-label="t().close" @click="closeCreateModal">×</button></div><form @submit.prevent="createDevice"><label>{{ t().newDevice }}<input v-model="newDevice.name" class="device-name-input" :placeholder="t().newDevice" autofocus required maxlength="64" /></label><label>{{ t().fingerprint }}<select v-model="newDevice.fingerprint"><option value="">chrome</option><option value="safari">safari</option><option value="ios">ios</option><option value="firefox">firefox</option><option value="edge">edge</option></select></label><div class="modal-actions"><button type="button" class="secondary" @click="closeCreateModal">{{ t().cancel }}</button><button type="submit" :disabled="busy || !newDevice.name.trim()">{{ t().createDevice }}</button></div></form></div></div>
      <div v-if="clientAction" class="modal-backdrop" @click.self="closeClientAction"><div class="modal modal-small" role="dialog" aria-modal="true"><div class="modal-header"><div><p class="eyebrow">{{ clientAction.client.name }}</p><h2>{{ t().action }}</h2></div><button class="icon-button" :aria-label="t().close" @click="closeClientAction">×</button></div><p>{{ actionTitle(clientAction.action) }}</p><p v-if="clientAction.action === 'revoke'" class="hint">{{ t().noUndo }}</p><div class="modal-actions"><button class="secondary" @click="closeClientAction">{{ t().cancel }}</button><button :class="clientAction.action === 'revoke' ? 'danger-fill' : ''" :disabled="busy" @click="confirmClientAction">{{ actionLabel(clientAction.action) }}</button></div></div></div>
      <div v-if="selectedProfile" class="modal-backdrop" @click.self="closeProfile"><div class="modal profile-modal" role="dialog" aria-modal="true"><div class="modal-header"><div><p class="eyebrow">{{ t().profiles }}</p><h2>{{ t().profile }}</h2></div><button class="icon-button" :aria-label="t().close" @click="closeProfile">×</button></div><label>{{ t().copyUri }}<textarea readonly :value="selectedProfile.uri"></textarea></label><img class="qr" :src="`/api/clients/${selectedProfile.client_id}/profile?format=qr`" :alt="t().qr" /><a class="download-link" :href="`/api/clients/${selectedProfile.client_id}/profile?format=json`">{{ t().download }}</a></div></div>
      <div v-if="pendingSettings" class="modal-backdrop" @click.self="pendingSettings = null"><div class="modal" role="dialog" aria-modal="true"><div class="modal-header"><div><p class="eyebrow">{{ t().settings }}</p><h2>{{ t().confirmation }}</h2></div><button class="icon-button" :aria-label="t().close" @click="pendingSettings = null">×</button></div><h3>{{ t().settingsDiff }}</h3><ul class="review-list"><li v-for="item in pendingSettings.diff" :key="item.field"><strong>{{ item.field }}</strong>: {{ item.from }} → {{ item.to }}</li></ul><h3>{{ t().consequences }}</h3><ul class="review-list"><li v-for="item in pendingSettings.consequences" :key="item">{{ item }}</li></ul><p v-if="pendingSettings.revoked_clients">{{ t().revokedClients }}: {{ pendingSettings.revoked_clients }}</p><label v-if="pendingSettings.requires_confirmation">{{ t().confirmation }} ({{ t().expected }} {{ pendingSettings.expected_confirmation }})<input v-model="pendingSettings.confirmation" autocomplete="off" /></label><div class="modal-actions"><button class="secondary" :disabled="busy" @click="pendingSettings = null">{{ t().cancel }}</button><button :disabled="busy || (pendingSettings.requires_confirmation && pendingSettings.confirmation !== pendingSettings.expected_confirmation)" @click="applySettings">{{ t().applySettings }}</button></div></div></div>
    </section>
  </main>
</template>

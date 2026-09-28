<script setup lang="ts">
import { inject, nextTick, onBeforeUnmount, onMounted, ref } from 'vue'
import { APIError } from './application/errors'
import type { EventSubscription, XrayEasyGateway } from './application/ports/xrayEasyGateway'
import { clientActionFor } from './domain/models'
import type { Client, ClientAction, ClientActionType, Settings, SettingsChange } from './domain/models'
import type { Admin, DiagnosticEntry, NodeStatus, ProfileDelivery, SetupStatus, TOTPSetup, TOTPStatus } from './application/models'
import { loadAuthenticatedDashboard, loadDiagnosticsSnapshot, loadNodeStatusSnapshot } from './application/services/dashboard'
import { formatBytes, formatTimestamp } from './presentation/format'
import { useI18n } from './presentation/i18n'
import { readTheme, persistTheme } from './presentation/theme'
import { xrayEasyGatewayKey } from './presentation/api'
import type { Section, Theme } from './presentation/models'

const setup = ref<SetupStatus | null>(null)
const admin = ref<Admin | null>(null)
const clients = ref<Client[]>([])
const newDevice = ref({ name: '', fingerprint: '' })
const selectedProfile = ref<ProfileDelivery | null>(null)
const copiedProfile = ref(false)
const error = ref('')
const busy = ref(false)
const { language, t, toggleLanguage } = useI18n()
const api = requireGateway(inject(xrayEasyGatewayKey))
const theme = ref<Theme>(readTheme())
const activeSection = ref<Section>('profiles')
const createModalOpen = ref(false)
const newDeviceNameInput = ref<HTMLInputElement | null>(null)
const clientAction = ref<ClientAction>(null)
const setupForm = ref({ username: 'admin', password: '', publicHost: '', publicPort: 443, realityTarget: 'www.cloudflare.com:443', realitySNI: 'www.cloudflare.com' })
const loginForm = ref({ username: 'admin', password: '', totpCode: '', recoveryCode: '' })
const totpStatus = ref<TOTPStatus | null>(null)
const totpSetup = ref<TOTPSetup | null>(null)
const totpConfirmCode = ref('')
const disableTOTPForm = ref({ password: '', code: '' })
const changePasswordForm = ref({ currentPassword: '', newPassword: '', confirmation: '' })
const lastBackup = ref('')
const settings = ref<Settings | null>(null)
const settingsForm = ref({ publicHost: '', realityTarget: '', realitySNI: '', clientFingerprint: 'chrome', rotatePrivateKey: false })
const pendingSettings = ref<SettingsChange | null>(null)
const nodeStatus = ref<NodeStatus | null>(null)
const diagnostics = ref<DiagnosticEntry[]>([])
const loginNeedsTOTP = ref(false)
const loginUsesRecovery = ref(false)
const successMessage = ref('')
let events: EventSubscription | null = null
let reconnectTimer: number | null = null
let disposed = false

/**
 * Return the configured application gateway or fail when dependency injection is missing.
 * @param gateway - The gateway provided by the application composition root.
 * @returns The gateway used by the UI.
 * @throws {Error} When the application gateway was not provided.
 */
function requireGateway(gateway: XrayEasyGateway | undefined): XrayEasyGateway {
  if (!gateway) throw new Error('XrayEasyGateway was not provided')
  return gateway
}

/**
 * Apply the selected theme and persist it for the next visit.
 * @param next - The theme to activate.
 */
function applyTheme(next: Theme) {
  theme.value = next
  persistTheme(next)
}

/**
 * Switch between the light and dark themes.
 */
function toggleTheme() { applyTheme(theme.value === 'dark' ? 'light' : 'dark') }

/**
 * Translate a server state into the status label shown in the UI.
 * @param state - The server state, when it is known.
 * @returns The localized status label.
 */
function statusLabel(state?: string) {
  const labels: Record<string, string> = { running: t().running, unavailable: t().unavailable, starting: t().starting, stopped: t().stopped }
  return labels[state ?? ''] ?? t().unknown
}

/**
 * Choose the visual tone for a server state.
 * @param state - The server state to classify.
 * @returns The semantic status tone used by the UI.
 */
function statusTone(state?: string) {
  if (state === 'running') return 'positive'
  if (state === 'unavailable' || state === 'stopped') return 'negative'
  return 'neutral'
}

/**
 * Count diagnostic entries at the requested severity.
 * @param level - The severity to count; warn also matches warning.
 * @returns The number of matching entries.
 */
function diagnosticCount(level: string) {
  const normalizedLevel = level.toLowerCase()
  return diagnostics.value.filter(entry => {
    const entryLevel = entry.level.toLowerCase()
    return entryLevel === normalizedLevel || (normalizedLevel === 'warn' && entryLevel === 'warning')
  }).length
}

/**
 * Choose the visual tone for a diagnostic severity.
 * @param level - The severity to classify.
 * @returns The semantic tone used by the UI.
 */
function diagnosticTone(level: string) {
  const normalized = level.toLowerCase()
  if (normalized === 'error') return 'negative'
  if (normalized === 'warn' || normalized === 'warning') return 'warning'
  return 'neutral'
}

/**
 * Replace any success notice with an error message.
 * @param cause - The failure to display.
 */
function showError(cause: unknown) { successMessage.value = ''; error.value = cause instanceof Error ? cause.message : 'Request failed' }
/**
 * Replace any error with a temporary success notice.
 * @param message - The localized success message.
 */
function showSuccess(message: string) { error.value = ''; successMessage.value = message; window.setTimeout(() => { successMessage.value = '' }, 3500) }

/**
 * Load setup state and, when authenticated, the dashboard data.
 */
async function load() {
  error.value = ''
  try {
    setup.value = await api.setup.status()
    if (setup.value.publicPort !== undefined) setupForm.value.publicPort = setup.value.publicPort
    if (setup.value.initialized) {
      try { admin.value = await api.auth.current() } catch { admin.value = null }
      if (admin.value) { await loadAuthenticated(); connectEvents() }
    }
  } catch (cause) { showError(cause) }
}
/**
 * Refresh all dashboard data for the current administrator.
 * @rejects {Error} When a required authenticated API request fails.
 */
async function loadAuthenticated() {
  const dashboard = await loadAuthenticatedDashboard(api)
  clients.value = dashboard.clients
  totpStatus.value = dashboard.totpStatus
  settings.value = dashboard.settings
  settingsForm.value = {
    publicHost: dashboard.settings.publicHost,
    realityTarget: dashboard.settings.realityTarget,
    realitySNI: dashboard.settings.realitySni,
    clientFingerprint: dashboard.settings.clientFingerprint,
    rotatePrivateKey: false,
  }
  nodeStatus.value = dashboard.nodeStatus
  diagnostics.value = dashboard.diagnostics
}
/**
 * Refresh the device list from the API.
 * @rejects {Error} When the device list request fails.
 */
async function loadClients() { clients.value = await api.clients.list() }
/**
 * Refresh the administrator two-factor status.
 * @rejects {Error} When the TOTP status request fails.
 */
async function loadTOTPStatus() { totpStatus.value = await api.auth.totpStatus() }
/**
 * Refresh the Xray node status.
 * @rejects {Error} When the node status request fails.
 */
async function loadStatus() { nodeStatus.value = await loadNodeStatusSnapshot(api) }
/**
 * Refresh the recent diagnostic entries.
 * @rejects {Error} When the diagnostics request fails.
 */
async function loadDiagnostics() { diagnostics.value = await loadDiagnosticsSnapshot(api) }
/**
 * Load current server settings and reset the editable form to those values.
 * @rejects {Error} When the settings request fails.
 */
async function loadSettings() {
  settings.value = await api.settings.get()
  settingsForm.value = { publicHost: settings.value.publicHost, realityTarget: settings.value.realityTarget, realitySNI: settings.value.realitySni, clientFingerprint: settings.value.clientFingerprint, rotatePrivateKey: false }
}
/**
 * Open the authenticated server event stream once and refresh UI data as events arrive.
 * @throws {Error} When the event stream cannot be opened.
 */
function connectEvents() {
  if (disposed || events || !admin.value) return
  events = api.events.connect({
    onStats: () => { if (admin.value) void loadClients() },
    onStatus: () => { if (admin.value) { void loadStatus(); void loadDiagnostics() } },
    onError: () => {
    stopEvents()
    if (admin.value && !disposed) {
      reconnectTimer = window.setTimeout(() => {
        reconnectTimer = null
        connectEvents()
      }, 3000)
    }
    },
  })
}
/**
 * Close the event stream and cancel any pending reconnect.
 */
function stopEvents() {
  if (reconnectTimer !== null) {
    window.clearTimeout(reconnectTimer)
    reconnectTimer = null
  }
  events?.close()
  events = null
}

/**
 * Submit the first-run settings and prepare the login form.
 */
async function initialize() {
  busy.value = true; error.value = ''
  try { await api.setup.initialize({ username: setupForm.value.username, password: setupForm.value.password, publicHost: setupForm.value.publicHost, publicPort: setupForm.value.publicPort, realityTarget: setupForm.value.realityTarget, realitySni: setupForm.value.realitySNI }); loginForm.value.username = setupForm.value.username; setup.value = { initialized: true } }
  catch (cause) { showError(cause) } finally { busy.value = false }
}
/**
 * Authenticate with the administrator password and load the dashboard.
 */
async function login() {
  busy.value = true; error.value = ''
  try { admin.value = await api.auth.login(loginForm.value.username, loginForm.value.password); loginNeedsTOTP.value = false; await loadAuthenticated(); connectEvents() }
  catch (cause) { if (cause instanceof APIError && cause.code === 'totp_required') loginNeedsTOTP.value = true; else showError(cause) } finally { busy.value = false }
}
/**
 * Authenticate with the password and the current TOTP code.
 */
async function loginTOTP() {
  busy.value = true; error.value = ''
  try { admin.value = await api.auth.loginWithTOTP(loginForm.value.username, loginForm.value.password, loginForm.value.totpCode); loginNeedsTOTP.value = false; await loadAuthenticated(); connectEvents() }
  catch (cause) { showError(cause) } finally { busy.value = false }
}
/**
 * Authenticate with the password and a one-time recovery code.
 */
async function loginRecovery() {
  busy.value = true; error.value = ''
  try { admin.value = await api.auth.loginWithRecoveryCode(loginForm.value.username, loginForm.value.password, loginForm.value.recoveryCode); loginNeedsTOTP.value = false; await loadAuthenticated(); connectEvents() }
  catch (cause) { showError(cause) } finally { busy.value = false }
}
/**
 * End the current administrator session and clear authenticated UI state.
 */
async function logout() { busy.value = true; error.value = ''; try { await api.auth.logout(); stopEvents(); admin.value = null; totpStatus.value = null } catch (cause) { showError(cause) } finally { busy.value = false } }
/**
 * End every administrator session and clear authenticated UI state.
 */
async function logoutAll() { busy.value = true; error.value = ''; try { await api.auth.logoutAll(); stopEvents(); admin.value = null; totpStatus.value = null } catch (cause) { showError(cause) } finally { busy.value = false } }

/**
 * Change the administrator password and return to the login screen after the server revokes all sessions.
 */
async function changePassword() {
  busy.value = true; error.value = ''
  try {
    await api.auth.changePassword(changePasswordForm.value.currentPassword, changePasswordForm.value.newPassword)
    stopEvents()
    loginForm.value.username = admin.value?.username ?? loginForm.value.username
    loginForm.value.password = ''
    loginNeedsTOTP.value = false
    loginUsesRecovery.value = false
    admin.value = null
    totpStatus.value = null
    changePasswordForm.value = { currentPassword: '', newPassword: '', confirmation: '' }
    showSuccess(t().passwordChanged)
  } catch (cause) { showError(cause) } finally { busy.value = false }
}

/**
 * Reset the new-device form, open its dialog, and focus the name field.
 */
function openCreateModal() {
  error.value = ''
  newDevice.value = { name: '', fingerprint: '' }
  createModalOpen.value = true
  void nextTick(() => newDeviceNameInput.value?.focus())
}
/**
 * Close the new-device dialog when no operation is in progress.
 */
function closeCreateModal() { if (!busy.value) createModalOpen.value = false }
/**
 * Create a device, add it to the list, and show its connection profile.
 */
async function createDevice() {
  busy.value = true; error.value = ''
  try { const created = await api.clients.create(newDevice.value.name, newDevice.value.fingerprint || undefined); clients.value.push(created); createModalOpen.value = false; await showProfile(created) }
  catch (cause) { showError(cause) } finally { busy.value = false }
}
/**
 * Load and display the connection profile for a device.
 * @param client - The device whose profile should be displayed.
 */
async function showProfile(client: Client) { try { copiedProfile.value = false; selectedProfile.value = await api.clients.profile(client.id) } catch (cause) { showError(cause) } }
/**
 * Close the profile dialog when no operation is in progress.
 */
function closeProfile() { if (!busy.value) { selectedProfile.value = null; copiedProfile.value = false } }
/**
 * Find the device associated with the currently displayed profile.
 * @returns The matching device, or undefined if it is no longer in the list.
 */
function selectedClient() { return clients.value.find(client => client.id === selectedProfile.value?.clientId) }
/**
 * Copy the selected VLESS URI to the clipboard and report the result.
 */
async function copyProfileUri() {
  if (!selectedProfile.value) return
  try { await navigator.clipboard.writeText(selectedProfile.value.uri); copiedProfile.value = true; showSuccess(t().profileCopied); window.setTimeout(() => { copiedProfile.value = false }, 2200) }
  catch (cause) { showError(cause) }
}
/**
 * Open confirmation for a valid device action.
 * @param client - The device to update.
 * @param action - The requested action, or null when no action is allowed.
 */
function openClientAction(client: Client, action: ClientActionType | null) { if (!action) return; error.value = ''; clientAction.value = { client, action } }
/**
 * Close the device-action dialog when no operation is in progress.
 */
function closeClientAction() { if (!busy.value) clientAction.value = null }
/**
 * Apply the confirmed device action and update the device list.
 */
async function confirmClientAction() {
  if (!clientAction.value) return
  const { client, action } = clientAction.value
  busy.value = true; error.value = ''
  try { const updated = await api.clients.setAction(client.id, action); const index = clients.value.findIndex(item => item.id === client.id); if (index >= 0) clients.value[index] = updated; clientAction.value = null }
  catch (cause) { showError(cause) } finally { busy.value = false }
}

/**
 * Create a backup and show its name in a success notice.
 */
async function createBackup() { busy.value = true; error.value = ''; try { const result = await api.backups.create(); lastBackup.value = result.name; showSuccess(t().backupReady) } catch (cause) { showError(cause) } finally { busy.value = false } }
/**
 * Request a settings preview and open the confirmation step.
 */
async function reviewSettings() {
  busy.value = true; error.value = ''; pendingSettings.value = null
  try { const result = await api.settings.preview({ publicHost: settingsForm.value.publicHost, realityTarget: settingsForm.value.realityTarget, realitySni: settingsForm.value.realitySNI, clientFingerprint: settingsForm.value.clientFingerprint, rotatePrivateKey: settingsForm.value.rotatePrivateKey }); pendingSettings.value = { ...result, confirmation: '' } }
  catch (cause) { showError(cause) } finally { busy.value = false }
}
/**
 * Apply the confirmed settings and refresh affected dashboard data.
 */
async function applySettings() {
  if (!pendingSettings.value) return
  busy.value = true; error.value = ''
  try { await api.settings.apply(pendingSettings.value.changeId, pendingSettings.value.confirmation); pendingSettings.value = null; await loadSettings(); await loadClients(); showSuccess(t().saved) }
  catch (cause) { showError(cause) } finally { busy.value = false }
}
/**
 * Request a new TOTP enrollment secret and QR code.
 */
async function startTOTPSetup() { busy.value = true; error.value = ''; try { totpSetup.value = await api.auth.beginTOTPSetup() } catch (cause) { showError(cause) } finally { busy.value = false } }
/**
 * Confirm TOTP enrollment with the code entered by the administrator.
 */
async function confirmTOTP() {
  if (!totpSetup.value) return
  busy.value = true; error.value = ''
  try { await api.auth.enableTOTP(totpSetup.value.setupToken, totpConfirmCode.value); totpSetup.value = null; totpConfirmCode.value = ''; await loadTOTPStatus() }
  catch (cause) { showError(cause) } finally { busy.value = false }
}
/**
 * Disable TOTP after server-side password and code verification, then end the session.
 */
async function disableTOTP() { busy.value = true; error.value = ''; try { await api.auth.disableTOTP(disableTOTPForm.value.password, disableTOTPForm.value.code); admin.value = null; totpStatus.value = null; disableTOTPForm.value = { password: '', code: '' }; stopEvents() } catch (cause) { showError(cause) } finally { busy.value = false } }

/**
 * Close the topmost active dialog when no operation is in progress.
 */
function closeActiveModal() {
  if (busy.value) return
  if (pendingSettings.value) { pendingSettings.value = null; return }
  if (selectedProfile.value) { closeProfile(); return }
  if (clientAction.value) { closeClientAction(); return }
  if (createModalOpen.value) closeCreateModal()
}
/**
 * Close the active dialog when the administrator presses Escape.
 * @param event - The keyboard event received from the window.
 */
function handleKeydown(event: KeyboardEvent) { if (event.key === 'Escape') closeActiveModal() }

onMounted(() => { disposed = false; applyTheme(theme.value); window.addEventListener('keydown', handleKeydown); void load() })
onBeforeUnmount(() => { disposed = true; stopEvents(); window.removeEventListener('keydown', handleKeydown) })
/**
 * Return the localized confirmation title for a device action.
 * @param action - The action to describe, when one is selected.
 * @returns The localized dialog title.
 */
function actionTitle(action?: ClientActionType) { if (action === 'enable') return t().enableConfirm; if (action === 'disable') return t().disableConfirm; return t().removeConfirm }
/**
 * Return the localized button label for a device action.
 * @param action - The action to label, when one is selected.
 * @returns The localized action label.
 */
function actionLabel(action?: ClientActionType) { if (action === 'enable') return t().enable; if (action === 'disable') return t().disable; return t().remove }
</script>

<template>
  <main class="shell" :aria-busy="busy">
    <header class="topbar">
      <div class="brand"><img class="brand-mark" :src="theme === 'dark' ? '/favicon-dark.svg' : '/favicon-light.svg'" alt="" aria-hidden="true" /><div class="brand-copy"><strong>{{ t().title }}</strong><span>{{ t().panelSubtitle }}</span></div></div>
      <div class="topbar-actions">
        <span v-if="admin" class="node-pill" :class="`node-pill-${statusTone(nodeStatus?.state)}`"><span class="status-dot" :class="{ online: nodeStatus?.state === 'running' }"></span>{{ statusLabel(nodeStatus?.state) }}</span>
        <button class="theme-toggle" :aria-label="theme === 'dark' ? t().useLightTheme : t().useDarkTheme" @click="toggleTheme"><span class="theme-icon" aria-hidden="true">{{ theme === 'dark' ? '☀' : '☾' }}</span><span>{{ theme === 'dark' ? t().useLightTheme : t().useDarkTheme }}</span></button>
        <button class="language" @click="toggleLanguage">{{ t().language }}</button>
      </div>
    </header>
    <section class="card error-card" v-if="error" role="alert" aria-live="assertive"><p class="error">{{ error }}</p></section>
    <section class="card success-card" v-if="successMessage" role="status" aria-live="polite"><p>{{ successMessage }}</p></section>
    <form class="card auth-card" v-if="!setup?.initialized" @submit.prevent="initialize">
      <h1>{{ t().setup }}</h1><label>{{ t().username }}<input v-model="setupForm.username" autocomplete="username" required /></label><label>{{ t().password }}<input v-model="setupForm.password" type="password" autocomplete="new-password" required /></label><label>{{ t().host }}<input v-model="setupForm.publicHost" placeholder="vpn.example.com" required /><small class="hint">{{ t().hostHint }}</small></label><label>{{ t().port }}<input v-model.number="setupForm.publicPort" type="number" readonly /></label><label>{{ t().target }}<input v-model="setupForm.realityTarget" placeholder="www.cloudflare.com:443" required /></label><label>{{ t().sni }}<input v-model="setupForm.realitySNI" placeholder="www.cloudflare.com" required /></label><button type="submit" :disabled="busy">{{ t().create }}</button>
    </form>
    <form class="card auth-card" v-else-if="!admin" @submit.prevent="loginNeedsTOTP ? (loginUsesRecovery ? loginRecovery() : loginTOTP()) : login()">
      <h1>{{ t().login }}</h1><label>{{ t().username }}<input v-model="loginForm.username" autocomplete="username" required /></label><label>{{ t().password }}<input v-model="loginForm.password" type="password" autocomplete="current-password" required /></label><template v-if="loginNeedsTOTP"><label v-if="!loginUsesRecovery">{{ t().loginCode }}<input v-model="loginForm.totpCode" inputmode="numeric" autocomplete="one-time-code" required /></label><label v-else>{{ t().recoveryCode }}<input v-model="loginForm.recoveryCode" autocomplete="one-time-code" required /></label><button type="submit" :disabled="busy">{{ t().signIn }}</button><button type="button" class="secondary" @click="loginUsesRecovery = !loginUsesRecovery">{{ loginUsesRecovery ? t().useTOTP : t().useRecovery }}</button></template><button v-else type="submit" :disabled="busy">{{ t().signIn }}</button>
    </form>
    <section class="card dashboard" v-else>
      <div class="dashboard-header"><div><p class="eyebrow">{{ t().title }}</p><h1>{{ t().profiles }}</h1></div><div class="header-actions"><button class="secondary" @click="logoutAll">{{ t().logoutAll }}</button><button class="secondary" @click="logout">{{ t().logout }}</button></div></div>
      <nav class="tabs" role="tablist" :aria-label="t().title"><button role="tab" :aria-selected="activeSection === 'profiles'" :class="{ active: activeSection === 'profiles' }" @click="activeSection = 'profiles'">{{ t().profiles }}</button><button role="tab" :aria-selected="activeSection === 'settings'" :class="{ active: activeSection === 'settings' }" @click="activeSection = 'settings'">{{ t().settings }}</button><button role="tab" :aria-selected="activeSection === 'diagnostics'" :class="{ active: activeSection === 'diagnostics' }" @click="activeSection = 'diagnostics'">{{ t().diagnostics }}</button><button role="tab" :aria-selected="activeSection === 'security'" :class="{ active: activeSection === 'security' }" @click="activeSection = 'security'">{{ t().security }}</button></nav>
      <section v-if="activeSection === 'profiles'" class="section-panel">
        <div class="section-heading"><div><p class="eyebrow">{{ t().profiles }}</p><h2>{{ clients.length }} {{ t().profileCount }}</h2><p class="muted">{{ t().traffic }} · {{ clients.filter(client => client.online).length }} {{ t().online }}</p></div><button @click="openCreateModal"><span class="button-icon" aria-hidden="true">+</span>{{ t().createProfile }}</button></div>
        <div v-if="!clients.length" class="empty-state"><span class="empty-icon" aria-hidden="true">⌁</span><strong>{{ t().emptyProfiles }}</strong><button @click="openCreateModal">{{ t().createProfile }}</button></div>
        <ul v-else class="devices">
          <li v-for="client in clients" :key="client.id" class="device-card">
            <div class="device-card-header"><div class="device-identity"><span class="device-status" :class="{ online: client.online, disabled: !client.enabled || client.revoked }"><span class="status-dot" :class="{ online: client.online }"></span></span><div class="device-main"><strong>{{ client.name }}</strong><span class="device-meta">{{ client.fingerprint || 'chrome' }} · {{ client.online ? t().online : t().offline }}</span></div></div><span class="status-badge" :class="{ positive: client.enabled && !client.revoked, muted: !client.enabled, negative: client.revoked }">{{ client.revoked ? t().revoked : client.enabled ? t().enabled : t().disabled }}</span></div>
            <div class="device-stats"><div class="device-stat"><span>{{ t().upload }}</span><strong>{{ formatBytes(client.uploadBytes) }}</strong></div><div class="device-stat"><span>{{ t().downloadTraffic }}</span><strong>{{ formatBytes(client.downloadBytes) }}</strong></div><div class="device-stat device-stat-wide"><span>{{ t().lastSeen }}</span><strong>{{ client.lastSeen ? formatTimestamp(client.lastSeen, language) : '—' }}</strong></div></div>
            <div class="device-card-footer"><span class="device-id">ID {{ client.id.slice(0, 8) }}</span><div class="device-actions"><button v-if="!client.revoked" class="secondary" @click="showProfile(client)">{{ t().profile }}</button><button v-if="!client.revoked" class="secondary" @click="openClientAction(client, clientActionFor(client))">{{ client.enabled ? t().disable : t().enable }}</button><button v-if="!client.revoked" class="danger" @click="openClientAction(client, 'revoke')">{{ t().remove }}</button></div></div>
          </li>
        </ul>
      </section>
      <section v-if="activeSection === 'settings' && settings" class="section-panel">
        <div class="section-heading"><div><p class="eyebrow">{{ t().settings }}</p><h2>{{ t().connectionSettings }}</h2><p class="muted">{{ settings.protocol.toUpperCase() }} · {{ settings.security.toUpperCase() }} · {{ settings.flow }}</p></div></div>
        <div class="settings-grid">
          <article class="settings-card">
            <div class="card-heading"><div><h3>{{ t().connectionSettings }}</h3><p class="hint">{{ t().connectionHelp }}</p></div><span class="settings-icon" aria-hidden="true">⌁</span></div>
            <label>{{ t().host }}<input v-model="settingsForm.publicHost" /><small class="hint">{{ t().hostHint }}</small></label>
            <label>{{ t().target }}<input v-model="settingsForm.realityTarget" /></label>
            <label>{{ t().sni }}<input v-model="settingsForm.realitySNI" /></label>
          </article>
          <article class="settings-card">
            <div class="card-heading"><div><h3>{{ t().profileDefaults }}</h3><p class="hint">{{ t().profileDefaultsHelp }}</p></div><span class="settings-icon" aria-hidden="true">✦</span></div>
            <label>{{ t().fingerprint }}<select v-model="settingsForm.clientFingerprint"><option value="chrome">chrome</option><option value="safari">safari</option><option value="ios">ios</option><option value="firefox">firefox</option><option value="edge">edge</option><option value="android">android</option><option value="random">random</option></select></label>
          </article>
          <article class="settings-card settings-card-danger">
            <div class="card-heading"><div><h3>{{ t().dangerousSettings }}</h3><p class="hint">{{ t().rotationHelp }}</p></div><span class="settings-icon" aria-hidden="true">!</span></div>
            <label class="checkbox"><input v-model="settingsForm.rotatePrivateKey" type="checkbox" /> {{ t().rotateKey }}</label>
            <p class="hint">{{ t().settingsWarning }}</p>
          </article>
        </div>
        <div class="section-actions"><button :disabled="busy" @click="reviewSettings">{{ t().saveSettings }}</button></div>
      </section>
      <section v-if="activeSection === 'diagnostics'" class="section-panel">
        <div class="section-heading"><div><p class="eyebrow">{{ t().diagnostics }}</p><h2>{{ t().diagnostics }}</h2><p class="muted">{{ t().restarts }}: {{ nodeStatus?.restartCount || 0 }}</p></div><button class="secondary" :disabled="busy" @click="loadStatus(); loadDiagnostics()">{{ t().refreshDiagnostics }}</button></div>
        <div class="diagnostics-overview">
          <article class="diagnostic-status-card" :class="`diagnostic-${statusTone(nodeStatus?.state)}`"><span class="status-icon" aria-hidden="true">{{ nodeStatus?.state === 'running' ? '✓' : '!' }}</span><div><span class="stat-label">{{ t().xrayState }}</span><strong>{{ statusLabel(nodeStatus?.state) }}</strong></div></article>
          <div class="diagnostic-summary"><span>{{ t().restarts }}: <strong>{{ nodeStatus?.restartCount || 0 }}</strong></span><span class="diagnostic-counter diagnostic-warning">{{ diagnosticCount('warn') }} {{ t().warnings }}</span><span class="diagnostic-counter diagnostic-negative">{{ diagnosticCount('error') }} {{ t().errors }}</span></div>
        </div>
        <div v-if="nodeStatus?.lastError || nodeStatus?.statsLastError" class="diagnostic-alerts"><p v-if="nodeStatus?.lastError" class="error">{{ nodeStatus.lastError }}</p><p v-if="nodeStatus?.statsLastError" class="error">{{ nodeStatus.statsLastError }}</p></div>
        <div class="diagnostics-feed"><div class="feed-heading"><h3>{{ t().recentEvents }}</h3><span class="muted">{{ diagnostics.length }}</span></div><ul v-if="diagnostics.length" class="diagnostics-list"><li v-for="entry in diagnostics" :key="`${entry.at}-${entry.component}-${entry.message}`" class="diagnostic-event"><div class="diagnostic-event-meta"><span class="diagnostic-level" :class="`diagnostic-level-${diagnosticTone(entry.level)}`">{{ entry.level }}</span><small>{{ formatTimestamp(entry.at, language) }} · {{ entry.component }}</small></div><span>{{ entry.message }}</span></li></ul><p v-else class="empty-state compact-empty">{{ t().noDiagnostics }}</p></div>
      </section>
      <section v-if="activeSection === 'security'" class="section-panel security-panel">
        <div class="section-heading"><div><p class="eyebrow">{{ t().security }}</p><h2>{{ t().security }}</h2><p class="muted">{{ t().totp }}: <strong>{{ totpStatus?.enabled ? t().totpEnabled : t().totpDisabled }}</strong></p></div></div>
        <div class="security-grid">
          <article class="security-card">
            <div class="card-heading"><div><h3>{{ t().passwordSecurityTitle }}</h3><p class="hint">{{ t().passwordSecurityHelp }}</p></div><span class="settings-icon" aria-hidden="true">⌑</span></div>
            <form @submit.prevent="changePassword">
              <label>{{ t().currentPassword }}<input v-model="changePasswordForm.currentPassword" type="password" autocomplete="current-password" required /></label>
              <label>{{ t().newPassword }}<input v-model="changePasswordForm.newPassword" type="password" autocomplete="new-password" minlength="12" required /></label>
              <label>{{ t().confirmNewPassword }}<input v-model="changePasswordForm.confirmation" type="password" autocomplete="new-password" minlength="12" required /></label>
              <p v-if="changePasswordForm.confirmation && changePasswordForm.newPassword !== changePasswordForm.confirmation" class="hint">{{ t().passwordMismatch }}</p>
              <button class="secondary security-action-button" type="submit" :disabled="busy || changePasswordForm.newPassword.length < 12 || changePasswordForm.newPassword !== changePasswordForm.confirmation">{{ t().changePassword }}</button>
            </form>
          </article>
          <article class="security-card">
            <div class="card-heading"><div><h3>{{ t().backupTitle }}</h3><p class="hint">{{ t().backupHelp }}</p></div><span class="settings-icon" aria-hidden="true">▣</span></div>
            <button class="secondary" :disabled="busy" @click="createBackup">{{ t().backup }}</button>
            <p v-if="lastBackup" class="backup-name">{{ t().backupCreated }}: {{ lastBackup }}</p>
          </article>
          <article class="security-card">
            <div class="card-heading"><div><h3>{{ t().totpTitle }}</h3><p class="hint">{{ t().totpHelp }}</p></div><span class="settings-icon" aria-hidden="true">⌑</span></div>
            <p class="security-status" :class="{ enabled: totpStatus?.enabled }"><span class="status-dot" :class="{ online: totpStatus?.enabled }"></span>{{ totpStatus?.enabled ? t().totpEnabled : t().totpDisabled }}</p>
            <template v-if="!totpStatus?.enabled && !totpSetup"><button class="secondary security-action-button" :disabled="busy" @click="startTOTPSetup">{{ t().enableTOTP }}</button></template>
            <template v-if="totpSetup"><p>{{ t().setupTOTP }}</p><div class="totp-setup-grid"><div v-if="totpSetup.qrPng" class="qr-panel totp-qr-panel"><span class="qr-label">{{ t().qr }}</span><img class="qr totp-qr" :src="`data:image/png;base64,${totpSetup.qrPng}`" :alt="t().qr" /></div><div class="totp-setup-fields"><label>{{ t().secret }}<input readonly :value="totpSetup.secret" /></label><label>otpauth URI<textarea readonly :value="totpSetup.otpauthUri"></textarea></label></div></div><p><strong>{{ t().recovery }}</strong></p><pre class="recovery-codes">{{ totpSetup.recoveryCodes.join('\n') }}</pre><label>{{ t().loginCode }}<input v-model="totpConfirmCode" inputmode="numeric" autocomplete="one-time-code" /></label><button :disabled="busy || !totpConfirmCode" @click="confirmTOTP">{{ t().confirmTOTP }}</button></template>
            <template v-if="totpStatus?.enabled"><p>{{ totpStatus.recoveryCodesRemaining }} {{ t().recoveryLeft }}</p><p>{{ t().disableTOTPHint }}</p><label>{{ t().password }}<input v-model="disableTOTPForm.password" type="password" autocomplete="current-password" /></label><label>{{ t().loginCode }}<input v-model="disableTOTPForm.code" inputmode="numeric" autocomplete="one-time-code" /></label><button class="danger" :disabled="busy" @click="disableTOTP">{{ t().disableTOTP }}</button></template>
          </article>
        </div>
      </section>

      <div v-if="createModalOpen" class="modal-backdrop" role="presentation" @click.self="closeCreateModal"><div class="modal" role="dialog" aria-modal="true" aria-labelledby="create-profile-title" tabindex="-1"><div class="modal-header"><div><p class="eyebrow">{{ t().profiles }}</p><h2 id="create-profile-title">{{ t().createProfile }}</h2></div><button class="icon-button" :aria-label="t().close" @click="closeCreateModal">×</button></div><form @submit.prevent="createDevice"><label>{{ t().newDevice }}<input ref="newDeviceNameInput" v-model="newDevice.name" class="device-name-input" :placeholder="t().newDevice" required maxlength="64" /></label><label>{{ t().fingerprint }}<select v-model="newDevice.fingerprint"><option value="">chrome</option><option value="safari">safari</option><option value="ios">ios</option><option value="firefox">firefox</option><option value="edge">edge</option></select></label><div class="modal-actions"><button type="button" class="secondary" @click="closeCreateModal">{{ t().cancel }}</button><button type="submit" :disabled="busy || !newDevice.name.trim()">{{ t().createDevice }}</button></div></form></div></div>
      <div v-if="clientAction" class="modal-backdrop" role="presentation" @click.self="closeClientAction"><div class="modal modal-small" role="dialog" aria-modal="true" aria-labelledby="client-action-title" tabindex="-1"><div class="modal-header"><div><p class="eyebrow">{{ clientAction.client.name }}</p><h2 id="client-action-title">{{ t().action }}</h2></div><button class="icon-button" :aria-label="t().close" @click="closeClientAction">×</button></div><p>{{ actionTitle(clientAction.action) }}</p><p v-if="clientAction.action === 'revoke'" class="hint">{{ t().noUndo }}</p><div class="modal-actions"><button class="secondary" @click="closeClientAction">{{ t().cancel }}</button><button :class="clientAction.action === 'revoke' ? 'danger-fill' : ''" :disabled="busy" @click="confirmClientAction">{{ actionLabel(clientAction.action) }}</button></div></div></div>
      <div v-if="selectedProfile" class="modal-backdrop" role="presentation" @click.self="closeProfile"><div class="modal profile-modal" role="dialog" aria-modal="true" aria-labelledby="profile-delivery-title" tabindex="-1"><div class="modal-header"><div><p class="eyebrow">{{ t().profiles }}</p><h2 id="profile-delivery-title">{{ t().profileFor }} {{ selectedClient()?.name || '' }}</h2></div><button class="icon-button" :aria-label="t().close" @click="closeProfile">×</button></div><p class="hint profile-hint">{{ t().scanHint }}</p><div class="profile-delivery"><div class="qr-panel"><span class="qr-label">{{ t().qr }}</span><img class="qr" :src="api.clients.profileQrUrl(selectedProfile.clientId)" :alt="t().qr" /></div><div class="profile-link-panel"><label>{{ t().copyUri }}<textarea readonly :value="selectedProfile.uri"></textarea></label><button class="secondary copy-button" @click="copyProfileUri"><span aria-hidden="true">⧉</span>{{ copiedProfile ? t().copied : t().copy }}</button><a class="download-link" :href="api.clients.profileJsonUrl(selectedProfile.clientId)"><span aria-hidden="true">↓</span>{{ t().jsonFile }}</a></div></div></div></div>
      <div v-if="pendingSettings" class="modal-backdrop" role="presentation" @click.self="pendingSettings = null"><div class="modal" role="dialog" aria-modal="true" aria-labelledby="settings-confirmation-title" tabindex="-1"><div class="modal-header"><div><p class="eyebrow">{{ t().settings }}</p><h2 id="settings-confirmation-title">{{ t().confirmation }}</h2></div><button class="icon-button" :aria-label="t().close" @click="pendingSettings = null">×</button></div><h3>{{ t().settingsDiff }}</h3><ul class="review-list"><li v-for="item in pendingSettings.diff" :key="item.field"><strong>{{ item.field }}</strong>: {{ item.from }} → {{ item.to }}</li></ul><h3>{{ t().consequences }}</h3><ul class="review-list"><li v-for="item in pendingSettings.consequences" :key="item">{{ item }}</li></ul><p v-if="pendingSettings.revokedClients">{{ t().revokedClients }}: {{ pendingSettings.revokedClients }}</p><label v-if="pendingSettings.requiresConfirmation">{{ t().confirmation }} ({{ t().expected }} {{ pendingSettings.expectedConfirmation }})<input v-model="pendingSettings.confirmation" autocomplete="off" /></label><div class="modal-actions"><button class="secondary" :disabled="busy" @click="pendingSettings = null">{{ t().cancel }}</button><button :disabled="busy || (pendingSettings.requiresConfirmation && pendingSettings.confirmation !== pendingSettings.expectedConfirmation)" @click="applySettings">{{ t().applySettings }}</button></div></div></div>
    </section>
  </main>
</template>

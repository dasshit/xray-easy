<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import type { HysteriaCertificateInfo, HysteriaSettings, HysteriaSettingsCommand, HysteriaSettingsPreview } from '../application/models'
import type { XrayEasyGateway } from '../application/ports/xrayEasyGateway'
import { translations } from './i18n/messages'
import type { UILanguage } from './i18n'
import { requireValue } from '../application/requireValue'
import { formatCertificateExpiry, selectedCertificateFile } from './hysteriaCertificate'

type PendingHysteriaChange = Extract<HysteriaSettingsPreview, { changed: true }> & { confirmation: string }

const props = defineProps<{ api: XrayEasyGateway; language: UILanguage }>()
const emit = defineEmits<{ error: [cause: unknown]; saved: [] }>()
const text = computed(() => translations[props.language])
const status = ref<HysteriaSettings | null>(null)
const busy = ref(false)
const pending = ref<PendingHysteriaChange | null>(null)
const stagedCertificate = ref<HysteriaCertificateInfo | null>(null)
const fullchainFile = ref<File | null>(null)
const privateKeyFile = ref<File | null>(null)
const form = ref<HysteriaSettingsCommand>({
  enabled: false,
  host: '',
  tlsMode: 'custom',
  tlsCertIp: '',
  tlsServerName: '',
  certificateId: '',
  udpIdleTimeout: 60,
  masqueradeType: 'off',
  masqueradeString: '',
})

/**
 * Load persisted Hysteria 2 settings and populate the editable form.
 * @rejects {Error} When the authenticated status request fails.
 */
async function loadSettings(): Promise<void> {
  busy.value = true
  try {
    const value = await props.api.hysteria.status()
    status.value = value
    stagedCertificate.value = null
    form.value = {
      enabled: value.enabled,
      host: value.host,
      tlsMode: value.tlsMode,
      tlsCertIp: value.tlsCertIp ?? '',
      tlsServerName: value.tlsServerName,
      certificateId: value.certificateId ?? '',
      udpIdleTimeout: value.udpIdleTimeout,
      masqueradeType: value.masqueradeType,
      masqueradeString: value.masqueradeString ?? '',
    }
  } catch (cause) {
    emit('error', cause)
  } finally {
    busy.value = false
  }
}

/**
 * Remember a certificate file selected in the upload form.
 * @param field - The certificate or private-key file slot.
 * @param event - The file input change event.
 */
function selectCertificateFile(field: 'fullchain' | 'privateKey', event: Event): void {
  const file = selectedCertificateFile(event.currentTarget)
  if (field === 'fullchain') fullchainFile.value = file
  else privateKeyFile.value = file
}

/**
 * Import a trusted PEM chain and its matching key as an immutable certificate version.
 */
async function uploadCertificate(): Promise<void> {
  const serverName = form.value.tlsServerName.trim() || form.value.host.trim()
  busy.value = true
  try {
    const result = await props.api.hysteria.uploadCertificate(
      requireValue(fullchainFile.value, 'Certificate chain file'),
      requireValue(privateKeyFile.value, 'Certificate private key'),
      serverName,
    )
    form.value.certificateId = result.certificateId
    stagedCertificate.value = result.certificate
    fullchainFile.value = null
    privateKeyFile.value = null
  } catch (cause) {
    emit('error', cause)
  } finally {
    busy.value = false
  }
}

/**
 * Generate a mkcert certificate for the selected public IPv4 address.
 */
async function generateCertificate(): Promise<void> {
  busy.value = true
  try {
    const result = await props.api.hysteria.generateCertificate(form.value.tlsCertIp)
    form.value.tlsMode = 'self-signed'
    form.value.tlsServerName = form.value.tlsCertIp
    form.value.certificateId = result.certificateId
    stagedCertificate.value = result.certificate
  } catch (cause) {
    emit('error', cause)
  } finally {
    busy.value = false
  }
}

/**
 * Validate and preview the proposed Hysteria 2 settings.
 */
async function reviewSettings(): Promise<void> {
  busy.value = true
  pending.value = null
  try {
    const result = await props.api.hysteria.preview(form.value)
    if (!result.changed) {
      status.value = result.settings
      return
    }
    pending.value = { ...result, confirmation: '' }
  } catch (cause) {
    emit('error', cause)
  } finally {
    busy.value = false
  }
}

/**
 * Apply the reviewed inbound update, then refresh the displayed status.
 */
async function applySettings(): Promise<void> {
  const staged = requireValue(pending.value, 'Hysteria settings preview')
  busy.value = true
  try {
    await props.api.hysteria.apply(staged.changeId, staged.confirmation)
    pending.value = null
    await loadSettings()
    emit('saved')
  } catch (cause) {
    emit('error', cause)
  } finally {
    busy.value = false
  }
}

/**
 * Return a localized label for the current transport state.
 * @returns The translated status text.
 */
function stateLabel(): string {
  switch (status.value?.state) {
    case 'on': return text.value.hysteriaStateOn
    case 'ready': return text.value.hysteriaStateReady
    case 'needs_certificate': return text.value.hysteriaStateNeedsCertificate
    case 'applying': return text.value.hysteriaStateApplying
    case 'renewal_due': return text.value.hysteriaStateRenewalDue
    case 'error': return text.value.hysteriaStateError
    default: return text.value.hysteriaStateOff
  }
}

onMounted(() => { void loadSettings() })
</script>

<template>
  <article id="hysteria-settings" class="settings-card hysteria-settings-card">
    <div class="card-heading">
      <div>
        <h3>{{ text.hysteriaTitle }}</h3>
        <p class="hint">{{ text.hysteriaHelp }}</p>
      </div>
      <span class="settings-icon" aria-hidden="true">↗</span>
    </div>
    <div v-if="status" class="hysteria-status-row">
      <span class="status-badge" :class="status.state === 'on' || status.state === 'ready' ? 'positive' : status.state === 'error' ? 'negative' : 'muted'">{{ stateLabel() }}</span>
      <span class="muted">{{ text.hysteriaPublicPort }}: {{ status.udpPort }}/UDP</span>
    </div>
    <p v-if="status?.runtimeError" class="error hysteria-inline-error">{{ status.runtimeError }}</p>
    <p v-if="status?.certificateError" class="hint hysteria-inline-warning">{{ status.certificateError }}</p>
    <label class="checkbox hysteria-enable-row"><input v-model="form.enabled" type="checkbox" /> {{ text.hysteriaEnable }}</label>
    <p class="hint">{{ text.hysteriaInboundImpact }}</p>
    <label>{{ text.hysteriaHost }}<input v-model="form.host" required autocomplete="url" /><small class="hint">{{ text.hysteriaHostHelp }}</small></label>
    <label>{{ text.hysteriaTLSMode }}
      <select v-model="form.tlsMode">
        <option value="custom">{{ text.hysteriaCustomCertificate }}</option>
        <option value="self-signed">{{ text.hysteriaMkcertCertificate }}</option>
        <option v-if="form.tlsMode === 'legacy'" value="legacy">{{ text.hysteriaLegacyCertificate }}</option>
      </select>
    </label>

    <template v-if="form.tlsMode === 'self-signed'">
      <label>{{ text.hysteriaCertificateIPv4 }}<input v-model="form.tlsCertIp" inputmode="decimal" placeholder="89.169.13.234" required @input="form.tlsServerName = form.tlsCertIp" /></label>
      <label>{{ text.hysteriaTLSServerName }}<input v-model="form.tlsServerName" readonly /></label>
      <p class="hysteria-security-note">{{ text.hysteriaInsecureWarning }}</p>
      <button class="secondary hysteria-action" :disabled="busy || !form.tlsCertIp.trim()" @click="generateCertificate">{{ text.hysteriaGenerateCertificate }}</button>
    </template>

    <template v-else>
      <label>{{ text.hysteriaTLSServerName }}<input v-model="form.tlsServerName" :placeholder="form.host" required /></label>
      <div class="hysteria-file-grid">
        <label>{{ text.hysteriaFullchain }}<input type="file" accept=".pem,.crt,application/x-pem-file" @change="selectCertificateFile('fullchain', $event)" /><small v-if="fullchainFile" class="hint">{{ fullchainFile.name }}</small></label>
        <label>{{ text.hysteriaPrivateKey }}<input type="file" accept=".pem,.key,application/x-pem-file" @change="selectCertificateFile('privateKey', $event)" /><small v-if="privateKeyFile" class="hint">{{ privateKeyFile.name }}</small></label>
      </div>
      <button class="secondary hysteria-action" :disabled="busy || !fullchainFile || !privateKeyFile || !(form.tlsServerName.trim() || form.host.trim())" @click="uploadCertificate">{{ text.hysteriaUploadCertificate }}</button>
      <p class="hint">{{ text.hysteriaCertificateTrustHelp }}</p>
    </template>

    <div v-if="stagedCertificate || status?.certificate" class="hysteria-certificate-meta">
      <strong>{{ text.hysteriaCertificateReady }}</strong>
      <span>{{ (stagedCertificate ?? status?.certificate)?.subject }}</span>
      <span>{{ text.hysteriaCertificateExpires }}: {{ formatCertificateExpiry(stagedCertificate ?? status?.certificate, language) }}</span>
      <span class="hysteria-fingerprint">SHA-256: {{ (stagedCertificate ?? status?.certificate)?.fingerprint }}</span>
    </div>

    <details class="hysteria-advanced">
      <summary>{{ text.hysteriaAdvanced }}</summary>
      <label>{{ text.hysteriaUDPTimeout }}<input v-model.number="form.udpIdleTimeout" type="number" min="10" max="600" required /><small class="hint">{{ text.hysteriaUDPTimeoutHelp }}</small></label>
      <label>{{ text.hysteriaMasquerade }}<select v-model="form.masqueradeType"><option value="off">{{ text.hysteriaMasqueradeOff }}</option><option value="string">{{ text.hysteriaMasqueradeText }}</option></select></label>
      <label v-if="form.masqueradeType === 'string'">{{ text.hysteriaMasqueradeBody }}<textarea v-model="form.masqueradeString" maxlength="4096" required /></label>
    </details>
    <div class="section-actions hysteria-save-row"><button :disabled="busy" @click="reviewSettings">{{ text.hysteriaReview }}</button></div>
  </article>

  <div v-if="pending" class="modal-backdrop" role="presentation" @click.self="pending = null">
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="hysteria-confirmation-title" tabindex="-1">
      <div class="modal-header"><div><p class="eyebrow">{{ text.hysteriaTitle }}</p><h2 id="hysteria-confirmation-title">{{ text.confirmation }}</h2></div><button class="icon-button" :aria-label="text.close" @click="pending = null">×</button></div>
      <h3>{{ text.settingsDiff }}</h3>
      <ul class="review-list"><li v-for="item in pending.diff" :key="item.field"><strong>{{ item.field }}</strong>: {{ item.from }} → {{ item.to }}</li></ul>
      <h3>{{ text.consequences }}</h3>
      <ul class="review-list"><li v-for="item in pending.consequences" :key="item">{{ item }}</li></ul>
      <label>{{ text.confirmation }} ({{ text.expected }} {{ pending.expectedConfirmation }})<input v-model="pending.confirmation" autocomplete="off" /></label>
      <div class="modal-actions"><button class="secondary" :disabled="busy" @click="pending = null">{{ text.cancel }}</button><button :disabled="busy || pending.confirmation !== pending.expectedConfirmation" @click="applySettings">{{ text.applySettings }}</button></div>
    </div>
  </div>
</template>

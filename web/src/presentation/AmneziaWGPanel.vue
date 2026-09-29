<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import type { XrayEasyGateway } from '../application/ports/xrayEasyGateway'
import type { AmneziaWGPeer, AmneziaWGStatus } from '../domain/models'
import { formatTimestamp } from './format'
import { translations } from './i18n/messages'
import type { UILanguage } from './i18n'

const props = defineProps<{ api: XrayEasyGateway; language: UILanguage }>()
const text = computed(() => translations[props.language])
const status = ref<AmneziaWGStatus | null>(null)
const peers = ref<AmneziaWGPeer[]>([])
const name = ref('')
const selectedProfile = ref<AmneziaWGPeer | null>(null)
const selectedRevoke = ref<AmneziaWGPeer | null>(null)
const busy = ref(false)
const loading = ref(false)
const error = ref('')
const validName = computed(() => /^[A-Za-z0-9-]{1,32}$/.test(name.value.trim()))

/** Load AWG status and, when the service is running, its peer list. */
async function refresh(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    status.value = await props.api.amneziawg.status()
    peers.value = status.value.available && status.value.running ? await props.api.amneziawg.listPeers() : []
  } catch {
    status.value = null
    peers.value = []
    error.value = text.value.awgUnavailable
  } finally {
    loading.value = false
  }
}

/** Create an AWG peer and open its profile delivery dialog. */
async function createPeer(): Promise<void> {
  const peerName = name.value.trim()
  if (!validName.value || status.value?.running !== true) return
  busy.value = true
  error.value = ''
  try {
    const peer = await props.api.amneziawg.createPeer({ name: peerName })
    name.value = ''
    await refresh()
    selectedProfile.value = peer
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : text.value.awgUnavailable
  } finally {
    busy.value = false
  }
}

/** Revoke the peer selected in the confirmation dialog and refresh the list. */
async function revokePeer(): Promise<void> {
  const peer = selectedRevoke.value
  if (!peer) return
  busy.value = true
  error.value = ''
  try {
    await props.api.amneziawg.removePeer(peer.name)
    selectedRevoke.value = null
    if (selectedProfile.value?.name === peer.name) selectedProfile.value = null
    await refresh()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : text.value.awgUnavailable
  } finally {
    busy.value = false
  }
}

/** Format a peer creation time in the selected interface language.
 * @param value - The peer creation timestamp from the service.
 * @returns The localized date and time.
 */
function createdAt(value: string): string { return formatTimestamp(value, props.language) }

onMounted(() => { void refresh() })
</script>

<template>
  <section class="section-panel">
    <div class="section-heading">
      <div><p class="eyebrow">{{ text.amneziawg }}</p><h2>{{ text.amneziawg }}</h2><p class="muted">{{ text.awgIntro }}</p></div>
      <button class="secondary" :disabled="loading" @click="refresh">{{ text.awgRefresh }}</button>
    </div>
    <p v-if="error" class="error" role="alert">{{ error }}</p>

    <article v-if="!status?.available || !status.running" class="settings-card">
      <div class="card-heading"><div><h3>{{ text.awgNotConfigured }}</h3><p class="hint">{{ text.awgStartHelp }}</p></div><span class="settings-icon" aria-hidden="true">⌁</span></div>
      <pre class="recovery-codes">./install.sh</pre>
    </article>

    <template v-else>
      <div class="settings-grid">
        <article class="settings-card">
          <div class="card-heading"><div><h3>{{ text.awgListener }}</h3><p class="hint">{{ status.publicHost }}:{{ status.publicPort }}/UDP</p></div><span class="settings-icon" aria-hidden="true">↗</span></div>
          <dl class="vmess-settings-list">
            <div><dt>{{ text.awgNetworks }}</dt><dd>{{ status.ipv4Network }}<br />{{ status.ipv6Network }}</dd></div>
            <div><dt>{{ text.awgPeers }}</dt><dd>{{ status.peerCount ?? peers.length }}</dd></div>
          </dl>
        </article>
        <article class="settings-card">
          <div class="card-heading"><div><h3>{{ text.awgCreatePeer }}</h3><p class="hint">{{ text.awgIntro }}</p></div><span class="settings-icon" aria-hidden="true">+</span></div>
          <form @submit.prevent="createPeer">
            <label>{{ text.awgPeerName }}<input v-model="name" required maxlength="32" pattern="[A-Za-z0-9-]{1,32}" autocomplete="off" /></label>
            <div class="section-actions"><button :disabled="busy || !validName">{{ text.awgCreatePeer }}</button></div>
          </form>
        </article>
      </div>

      <div class="diagnostics-feed">
        <div class="feed-heading"><h3>{{ text.awgPeers }}</h3><span class="muted">{{ peers.length }}</span></div>
        <ul v-if="peers.length" class="devices">
          <li v-for="peer in peers" :key="peer.name" class="device-card">
            <div class="device-card-header"><div class="device-identity"><div class="device-main"><strong>{{ peer.name }}</strong><span class="device-meta">{{ peer.ipv4 }} · {{ peer.ipv6 }} · {{ createdAt(peer.createdAt) }}</span></div></div></div>
            <div class="device-card-footer"><div class="device-actions"><button class="secondary" @click="selectedProfile = peer">{{ text.awgProfile }}</button><button class="danger" @click="selectedRevoke = peer">{{ text.awgRevoke }}</button></div></div>
          </li>
        </ul>
        <p v-else class="empty-state compact-empty">{{ text.awgEmpty }}</p>
      </div>
    </template>

    <div v-if="selectedProfile" class="modal-backdrop" role="presentation" @click.self="selectedProfile = null">
      <div class="modal modal-small" role="dialog" aria-modal="true" aria-labelledby="awg-profile-title">
        <div class="modal-header"><div><p class="eyebrow">{{ selectedProfile.name }}</p><h2 id="awg-profile-title">{{ text.awgProfile }}</h2></div><button class="icon-button" :aria-label="text.close" @click="selectedProfile = null">×</button></div>
        <p class="hint">{{ text.awgProfileHelp }}</p>
        <div class="qr-panel"><img class="qr" :src="api.amneziawg.profileQrUrl(selectedProfile.name)" :alt="text.qr" /></div>
        <div class="modal-actions"><a class="secondary" :href="api.amneziawg.profileUrl(selectedProfile.name)" download>{{ text.awgDownloadProfile }}</a><button class="secondary" @click="selectedProfile = null">{{ text.close }}</button></div>
      </div>
    </div>

    <div v-if="selectedRevoke" class="modal-backdrop" role="presentation" @click.self="selectedRevoke = null">
      <div class="modal modal-small" role="dialog" aria-modal="true" aria-labelledby="awg-revoke-title">
        <div class="modal-header"><div><p class="eyebrow">{{ selectedRevoke.name }}</p><h2 id="awg-revoke-title">{{ text.awgRevoke }}</h2></div><button class="icon-button" :aria-label="text.close" @click="selectedRevoke = null">×</button></div>
        <p>{{ text.awgConfirmRevoke }}</p>
        <div class="modal-actions"><button class="secondary" :disabled="busy" @click="selectedRevoke = null">{{ text.cancel }}</button><button class="danger-fill" :disabled="busy" @click="revokePeer">{{ text.awgRevoke }}</button></div>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { ProfileDelivery } from '../application/models'
import type { Client } from '../domain/models'
import { formatTimestamp } from './format'
import { translations } from './i18n/messages'
import type { UILanguage } from './i18n'

const props = defineProps<{
  profile: ProfileDelivery
  client: Client | undefined
  language: UILanguage
  vlessQrUrl: string
  hysteriaQrUrl: string
  jsonUrl: string
  copiedVless: boolean
  copiedHysteria: boolean
}>()
const emit = defineEmits<{ close: []; copyVless: []; copyHysteria: [] }>()
const text = computed(() => translations[props.language])
const vlessUri = computed(() => props.profile.protocol === 'hysteria2' ? undefined : props.profile.uri)
const hysteriaUri = computed(() => props.profile.protocol === 'vless' ? undefined : props.profile.hysteriaUri)
const hasJsonProfile = computed(() => props.profile.protocol === 'vless' || (props.profile.protocol === 'legacy_dual' && props.profile.json !== undefined))

/**
 * Return the display label for a legacy or protocol-specific profile.
 * @returns The translated profile protocol name.
 */
function profileLabel(): string {
  if (props.profile.protocol === 'legacy_dual') return text.value.legacyDual
  return props.profile.protocol === 'hysteria2' ? text.value.hysteria2Profile : 'VLESS + REALITY'
}
</script>

<template>
  <div class="modal-backdrop" role="presentation" @click.self="emit('close')">
    <div class="modal profile-modal" role="dialog" aria-modal="true" aria-labelledby="profile-delivery-title" tabindex="-1">
      <div class="modal-header">
        <div><p class="eyebrow">{{ profileLabel() }}</p><h2 id="profile-delivery-title">{{ text.profileFor }} {{ client?.name || '' }}</h2></div>
        <button class="icon-button" type="button" :aria-label="text.close" @click="emit('close')">×</button>
      </div>
      <p class="hint profile-hint">{{ text.scanHint }}</p>
      <div class="profile-connection" :class="client?.online ? 'is-online' : 'is-offline'">
        <strong v-if="client?.online">{{ text.connectionOnline }}</strong>
        <template v-else-if="client?.lastSeen"><strong>{{ text.offline }}</strong><p>{{ text.connectionLastSeen }}: {{ formatTimestamp(client.lastSeen, language) }}</p></template>
        <template v-else><strong>{{ text.connectionPending }}</strong><p>{{ text.connectionPendingHelp }}</p></template>
      </div>
      <div v-if="vlessUri" class="profile-delivery">
        <div class="qr-panel"><span class="qr-label">VLESS + REALITY</span><img class="qr" :src="vlessQrUrl" :alt="text.qr" /></div>
        <div class="profile-link-panel">
          <label>{{ text.copyUri }}<textarea readonly :value="vlessUri"></textarea></label>
          <button class="secondary copy-button" type="button" @click="emit('copyVless')"><span aria-hidden="true">⧉</span>{{ copiedVless ? text.copied : text.copy }}</button>
          <a v-if="hasJsonProfile" class="download-link" :href="jsonUrl"><span aria-hidden="true">↓</span>{{ text.jsonFile }}</a>
        </div>
      </div>
      <div v-if="hysteriaUri" class="profile-delivery hysteria-delivery">
        <div class="qr-panel"><span class="qr-label">{{ text.hysteria2Profile }}</span><img class="qr" :src="hysteriaQrUrl" :alt="text.qr" /></div>
        <div class="profile-link-panel">
          <label>{{ text.hysteria2Uri }}<textarea readonly :value="hysteriaUri"></textarea></label>
          <button class="secondary copy-button" type="button" @click="emit('copyHysteria')"><span aria-hidden="true">⧉</span>{{ copiedHysteria ? text.copied : text.copyHysteria2 }}</button>
          <p class="hint">{{ text.hysteria2Help }}</p>
        </div>
      </div>
    </div>
  </div>
</template>

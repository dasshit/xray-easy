<script setup lang="ts">
import { computed, nextTick, onMounted, ref } from 'vue'
import type { CreateClientCommand } from '../application/models'
import { translations } from './i18n/messages'
import type { UILanguage } from './i18n'

const props = defineProps<{ language: UILanguage; hysteriaAvailable: boolean; vmessAvailable: boolean; shadowsocksAvailable?: boolean; awgAvailable?: boolean; busy: boolean }>()
const emit = defineEmits<{
  cancel: []
  submit: [command: CreateClientCommand]
  openSettings: []
}>()
const text = computed(() => translations[props.language])
const nameInput = ref<HTMLInputElement | null>(null)
const form = ref<{ name: string; protocol: 'vless' | 'vmess' | 'hysteria2' | 'shadowsocks' | 'amneziawg'; fingerprint: string; auth: string }>({ name: '', protocol: 'vless', fingerprint: '', auth: '' })

/** Focus the device name field when the dialog appears. */
onMounted(() => { void nextTick(() => nameInput.value?.focus()) })

/** Submit only the options belonging to the selected transport. */
function submit(): void {
  const name = form.value.name.trim()
  if (!name || (form.value.protocol === 'hysteria2' && !props.hysteriaAvailable) || (form.value.protocol === 'vmess' && !props.vmessAvailable) || (form.value.protocol === 'shadowsocks' && !props.shadowsocksAvailable)) return
  if (form.value.protocol === 'amneziawg' && !props.awgAvailable) return
  if (form.value.protocol === 'vless') {
    emit('submit', { name, protocol: 'vless', ...(form.value.fingerprint ? { fingerprint: form.value.fingerprint } : {}) })
    return
  }
  if (form.value.protocol === 'vmess') {
    emit('submit', { name, protocol: 'vmess' })
    return
  }
  if (form.value.protocol === 'hysteria2') {
    emit('submit', { name, protocol: 'hysteria2', ...(form.value.auth.trim() ? { auth: form.value.auth.trim() } : {}) })
    return
  }
  if (form.value.protocol === 'shadowsocks') {
    emit('submit', { name, protocol: 'shadowsocks' })
    return
  }
  emit('submit', { name, protocol: 'amneziawg' })
}
</script>

<template>
  <div class="modal-backdrop" role="presentation" @click.self="emit('cancel')">
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="create-profile-title" tabindex="-1">
      <div class="modal-header">
        <div><p class="eyebrow">{{ text.profiles }}</p><h2 id="create-profile-title">{{ text.createProfile }}</h2></div>
        <button class="icon-button" type="button" :aria-label="text.close" @click="emit('cancel')">×</button>
      </div>
      <form @submit.prevent="submit">
        <label>
          {{ text.newDevice }}
          <input ref="nameInput" v-model="form.name" class="device-name-input" :placeholder="text.newDevice" required maxlength="64" pattern="[A-Za-z0-9-]{1,64}" autocomplete="off" />
        </label>
        <label>
          {{ text.profileProtocol }}
          <select v-model="form.protocol" data-testid="profile-protocol">
            <option value="vless">VLESS + REALITY</option>
            <option value="vmess" :disabled="!vmessAvailable">VMess + TLS</option>
            <option value="hysteria2" :disabled="!hysteriaAvailable">Hysteria 2</option>
            <option value="shadowsocks" :disabled="!shadowsocksAvailable">Shadowsocks</option>
            <option value="amneziawg" :disabled="!awgAvailable">AmneziaWG</option>
          </select>
        </label>
        <p v-if="!hysteriaAvailable && form.protocol !== 'vmess' && form.protocol !== 'shadowsocks' && form.protocol !== 'amneziawg'" class="hint" role="status">
          {{ text.hysteriaUnavailable }}
          <button class="text-button" type="button" @click="emit('openSettings')">{{ text.hysteriaSettingsLink }}</button>
        </p>
        <p v-if="form.protocol === 'vmess' && !vmessAvailable" class="hint" role="status">
          {{ text.vmessUnavailable }}
          <button class="text-button" type="button" @click="emit('openSettings')">{{ text.hysteriaSettingsLink }}</button>
        </p>
        <template v-if="form.protocol === 'vless'">
          <label>
            {{ text.fingerprint }}
            <select v-model="form.fingerprint">
              <option value="">chrome ({{ text.defaultValue }})</option>
              <option value="safari">safari</option>
              <option value="ios">ios</option>
              <option value="firefox">firefox</option>
              <option value="edge">edge</option>
            </select>
          </label>
          <p class="hint">{{ text.profileCreateSummaryVless }}</p>
        </template>
        <template v-else-if="form.protocol === 'hysteria2'">
          <p class="hint">{{ text.profileCreateSummaryHysteria }}</p>
          <details class="profile-advanced">
            <summary>{{ text.hysteriaAdvanced }}</summary>
            <label>
              {{ text.profileAuth }}
              <input v-model="form.auth" type="password" autocomplete="new-password" maxlength="256" />
              <small class="hint">{{ text.profileAuthHelp }}</small>
            </label>
          </details>
        </template>
        <template v-else-if="form.protocol === 'vmess'">
          <p class="hint">{{ text.profileCreateSummaryVMess }}</p>
        </template>
        <template v-else-if="form.protocol === 'shadowsocks'">
          <p class="hint">{{ text.profileCreateSummaryShadowsocks }}</p>
          <p v-if="!shadowsocksAvailable" class="hint" role="status">{{ text.shadowsocksUnavailable }} <button class="text-button" type="button" @click="emit('openSettings')">{{ text.shadowsocksSettingsLink }}</button></p>
        </template>
        <template v-else>
          <p class="hint">{{ text.profileCreateSummaryAmneziaWG }}</p>
          <p v-if="!awgAvailable" class="hint" role="status">{{ text.awgUnavailable }}</p>
        </template>
        <div class="modal-actions">
          <button class="secondary" type="button" :disabled="busy" @click="emit('cancel')">{{ text.cancel }}</button>
          <button type="submit" :disabled="busy || !form.name.trim() || (form.protocol === 'hysteria2' && !hysteriaAvailable) || (form.protocol === 'vmess' && !vmessAvailable) || (form.protocol === 'shadowsocks' && !shadowsocksAvailable) || (form.protocol === 'amneziawg' && !awgAvailable)">{{ text.createDevice }}</button>
        </div>
      </form>
    </div>
  </div>
</template>

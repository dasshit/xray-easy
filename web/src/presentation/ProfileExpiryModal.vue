<script setup lang="ts">
import { computed, ref } from 'vue'
import type { Client } from '../domain/models'
import { translations } from './i18n/messages'
import type { UILanguage } from './i18n'
import ExpirySelector from './ExpirySelector.vue'
import { vModalFocus } from './modalFocus'

const props = defineProps<{ client: Client; language: UILanguage; busy: boolean }>()
const emit = defineEmits<{
  close: []
  save: [expiresAt: string | undefined]
}>()
const text = computed(() => translations[props.language])
const expiresAt = ref(props.client.expiresAt)
const expiryIsValid = ref(props.client.expired !== true)

/** Save the selected deadline; the parent applies it without re-enabling access. */
function submit(): void {
  if (!expiryIsValid.value) return
  emit('save', expiresAt.value)
}
</script>

<template>
  <div class="modal-backdrop" role="presentation" @click.self="emit('close')">
    <div v-modal-focus class="modal modal-small" role="dialog" aria-modal="true" aria-labelledby="expiry-modal-title" tabindex="-1">
      <div class="modal-header">
        <div><p class="eyebrow">{{ client.name }}</p><h2 id="expiry-modal-title">{{ text.expiryDialogTitle }}</h2></div>
        <button class="icon-button" type="button" :aria-label="text.close" @click="emit('close')">×</button>
      </div>
      <form @submit.prevent="submit">
        <ExpirySelector v-model="expiresAt" :language="language" @valid-change="expiryIsValid = $event" />
        <div class="modal-actions">
          <button class="secondary" type="button" :disabled="busy" @click="emit('close')">{{ text.cancel }}</button>
          <button type="submit" :disabled="busy || !expiryIsValid">{{ text.saveExpiry }}</button>
        </div>
      </form>
    </div>
  </div>
</template>

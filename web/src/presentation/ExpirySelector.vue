<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { translations } from './i18n/messages'
import type { UILanguage } from './i18n'

const props = defineProps<{ language: UILanguage; modelValue?: string | undefined }>()
const emit = defineEmits<{
  'update:modelValue': [value: string | undefined]
  validChange: [valid: boolean]
}>()
const text = computed(() => translations[props.language])
const preset = ref<'never' | '24-hours' | '7-days' | '30-days' | 'custom'>('never')
const localDateTime = ref('')
const minimumDateTime = computed(() => toLocalDateTime(new Date()))
const customDateIsValid = computed(() => {
  if (preset.value !== 'custom') return true
  const value = new Date(localDateTime.value)
  return !Number.isNaN(value.getTime()) && value.getTime() > Date.now()
})

/** Initialize the selector with the profile's existing expiry, if any. */
onMounted(() => {
  if (props.modelValue !== undefined && props.modelValue !== '') {
    preset.value = 'custom'
    localDateTime.value = toLocalDateTime(new Date(props.modelValue))
    emit('validChange', customDateIsValid.value)
  }
})

/**
 * Convert a date into the browser-local value expected by datetime-local inputs.
 * @param value - The date to render in the local input.
 * @returns A local date-time string with minute precision.
 */
function toLocalDateTime(value: Date): string {
  const local = new Date(value.getTime() - value.getTimezoneOffset() * 60_000)
  return local.toISOString().slice(0, 16)
}

/** Apply a preset or publish the selected custom expiry to the parent form. */
function updateExpiry(): void {
  const presetDurations: Partial<Record<typeof preset.value, number>> = {
    '24-hours': 24 * 60 * 60 * 1000,
    '7-days': 7 * 24 * 60 * 60 * 1000,
    '30-days': 30 * 24 * 60 * 60 * 1000,
  }
  const duration = presetDurations[preset.value]
  if (duration !== undefined) {
    emit('update:modelValue', new Date(Date.now() + duration).toISOString())
    emit('validChange', true)
    return
  }
  if (preset.value === 'never') {
    emit('update:modelValue', undefined)
    emit('validChange', true)
    return
  }
  if (!localDateTime.value) localDateTime.value = toLocalDateTime(new Date(Date.now() + 24 * 60 * 60 * 1000))
  const customDate = new Date(localDateTime.value)
  const valid = !Number.isNaN(customDate.getTime()) && customDate.getTime() > Date.now()
  emit('update:modelValue', valid ? customDate.toISOString() : undefined)
  emit('validChange', valid)
}
</script>

<template>
  <fieldset class="expiry-selector">
    <legend>{{ text.profileExpiry }}</legend>
    <label>
      {{ text.profileExpiry }}
      <select v-model="preset" data-testid="expiry-preset" @change="updateExpiry">
        <option value="never">{{ text.expiryNever }}</option>
        <option value="24-hours">{{ text.expiry24Hours }}</option>
        <option value="7-days">{{ text.expiry7Days }}</option>
        <option value="30-days">{{ text.expiry30Days }}</option>
        <option value="custom">{{ text.expiryCustom }}</option>
      </select>
    </label>
    <label v-if="preset === 'custom'">
      {{ text.expiryDateTime }}
      <input v-model="localDateTime" type="datetime-local" :min="minimumDateTime" data-testid="expiry-custom" @input="updateExpiry" />
    </label>
    <p class="hint">{{ text.expiryHelp }}</p>
    <p v-if="!customDateIsValid" class="error" role="alert">{{ text.expiryInvalid }}</p>
  </fieldset>
</template>

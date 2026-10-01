import type { UILanguage } from './i18n'

/**
 * Format a byte count using a compact binary unit.
 * @param value - The number of bytes to format.
 * @returns A human-readable value using B, KB, MB, GB, or TB.
 */
export function formatBytes(value: number): string {
  if (!value) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let amount = value
  let unit = 0
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024
    unit += 1
  }
  return `${amount.toFixed(amount >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`
}

/** Format a sampled transfer rate in binary bytes per second.
 * @param value - The measured number of bytes transferred per second.
 * @returns A compact value suffixed with `/s`.
 */
export function formatRate(value: number): string {
  return `${formatBytes(Math.max(0, value))}/s`
}

/**
 * Format a timestamp using the selected interface locale.
 * @param value - The timestamp to format, when one is available.
 * @param language - The interface language that selects the locale.
 * @returns A localized date and time, or an empty string when no timestamp is present.
 */
export function formatTimestamp(value: string | undefined, language: UILanguage): string {
  if (value === undefined || value === '') return ''
  const locales: Record<UILanguage, string> = {
    ru: 'ru-RU', en: 'en-US', de: 'de-DE', es: 'es-ES', 'pt-BR': 'pt-BR', fr: 'fr-FR', tr: 'tr-TR', fa: 'fa-IR', ar: 'ar', 'zh-CN': 'zh-CN', uk: 'uk-UA', pl: 'pl-PL',
  }
  return new Date(value).toLocaleString(locales[language])
}

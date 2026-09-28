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

/**
 * Format a timestamp using the selected interface locale.
 * @param value - The timestamp to format, when one is available.
 * @param language - The interface language that selects the locale.
 * @returns A localized date and time, or an empty string when no timestamp is present.
 */
export function formatTimestamp(value: string | undefined, language: 'en' | 'ru'): string {
  if (value === undefined || value === '') return ''
  return new Date(value).toLocaleString(language === 'ru' ? 'ru-RU' : 'en-US')
}

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

export function formatTimestamp(value: string | undefined, language: 'en' | 'ru'): string {
  if (!value) return ''
  return new Date(value).toLocaleString(language === 'ru' ? 'ru-RU' : 'en-US')
}

import type { Theme } from '../domain/models'

const themeStorageKey = 'xray-easy-theme'
const languageStorageKey = 'xray-easy-language'

export type UILanguage = 'en' | 'ru'

export function readTheme(): Theme {
  if (typeof window === 'undefined') return 'light'
  const stored = window.localStorage.getItem(themeStorageKey)
  if (stored === 'light' || stored === 'dark') return stored
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

export function persistTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme
  window.localStorage.setItem(themeStorageKey, theme)
}

export function readLanguage(): UILanguage {
  if (typeof window === 'undefined') return 'en'
  const stored = window.localStorage.getItem(languageStorageKey)
  if (stored === 'en' || stored === 'ru') return stored
  return window.navigator.language.toLowerCase().startsWith('ru') ? 'ru' : 'en'
}

export function persistLanguage(language: UILanguage): void {
  window.localStorage.setItem(languageStorageKey, language)
}

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

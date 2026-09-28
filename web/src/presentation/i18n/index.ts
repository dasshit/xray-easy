import { ref } from 'vue'
import { translations } from './messages'

export type UILanguage = 'en' | 'ru'
const languageStorageKey = 'xray-easy-language'

export function readLanguage(): UILanguage {
  if (typeof window === 'undefined') return 'en'
  const stored = window.localStorage.getItem(languageStorageKey)
  if (stored === 'en' || stored === 'ru') return stored
  return window.navigator.language.toLowerCase().startsWith('ru') ? 'ru' : 'en'
}

export function persistLanguage(language: UILanguage): void {
  window.localStorage.setItem(languageStorageKey, language)
}

export function useI18n() {
  const language = ref<UILanguage>(readLanguage())
  const t = () => translations[language.value]

  function changeLanguage(next: UILanguage) {
    language.value = next
    persistLanguage(next)
  }

  function toggleLanguage() {
    changeLanguage(language.value === 'en' ? 'ru' : 'en')
  }

  return { language, t, changeLanguage, toggleLanguage }
}

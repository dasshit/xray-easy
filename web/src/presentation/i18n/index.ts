import { ref } from 'vue'
import { isUILanguage, languageOptions, translations } from './messages'
import type { UILanguage } from './messages'

export type { UILanguage } from './messages'
export { isUILanguage } from './messages'
const languageStorageKey = 'xray-easy-language'

/**
 * Apply the selected locale and text direction to the document.
 * @param language - The active interface language.
 */
function applyDocumentLanguage(language: UILanguage): void {
  if (typeof document === 'undefined') return
  document.documentElement.lang = language
  document.documentElement.dir = language === 'ar' || language === 'fa' ? 'rtl' : 'ltr'
}

/**
 * Read the saved interface language or infer one from the browser locale.
 * @returns The selected supported interface language.
 */
export function readLanguage(): UILanguage {
  if (typeof window === 'undefined') return 'en'
  const stored = window.localStorage.getItem(languageStorageKey)
  if (isUILanguage(stored)) return stored
  const browserLanguage = window.navigator.language.toLowerCase()
  const exact = languageOptions.find(option => option.code.toLowerCase() === browserLanguage)
  if (exact) return exact.code
  const base = browserLanguage.split('-')[0]
  const matchingBase = languageOptions.find(option => option.code.toLowerCase().split('-')[0] === base)
  return matchingBase?.code ?? 'en'
}

/**
 * Save the selected interface language in browser storage.
 * @param language - The language to persist.
 */
export function persistLanguage(language: UILanguage): void {
  window.localStorage.setItem(languageStorageKey, language)
  applyDocumentLanguage(language)
}

/**
 * Create reactive language state and translation helpers for a component.
 * @returns The active language, translation lookup, and language-change actions.
 */
export function useI18n() {
  const language = ref<UILanguage>(readLanguage())
  applyDocumentLanguage(language.value)
  /**
   * Return the translation dictionary for the current reactive language.
   * @returns The localized message dictionary.
   */
  function t() {
    return translations[language.value]
  }

  /**
   * Change the reactive language and persist the choice.
   * @param next - The language to activate.
   */
  function changeLanguage(next: UILanguage) {
    language.value = next
    persistLanguage(next)
  }

  /**
   * Switch the interface between English and Russian.
   */
  function toggleLanguage() {
    changeLanguage(language.value === 'en' ? 'ru' : 'en')
  }

  return { language, t, changeLanguage, toggleLanguage, languageOptions }
}

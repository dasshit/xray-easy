import { ref } from 'vue'
import { translations } from './messages'

export type UILanguage = 'en' | 'ru'
const languageStorageKey = 'xray-easy-language'

/**
 * Read the saved interface language or infer Russian from the browser locale.
 * @returns The selected Russian or English interface language.
 */
export function readLanguage(): UILanguage {
  if (typeof window === 'undefined') return 'en'
  const stored = window.localStorage.getItem(languageStorageKey)
  if (stored === 'en' || stored === 'ru') return stored
  return window.navigator.language.toLowerCase().startsWith('ru') ? 'ru' : 'en'
}

/**
 * Save the selected interface language in browser storage.
 * @param language - The language to persist.
 */
export function persistLanguage(language: UILanguage): void {
  window.localStorage.setItem(languageStorageKey, language)
}

/**
 * Create reactive language state and translation helpers for a component.
 * @returns The active language, translation lookup, and language-change actions.
 */
export function useI18n() {
  const language = ref<UILanguage>(readLanguage())
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

  return { language, t, changeLanguage, toggleLanguage }
}

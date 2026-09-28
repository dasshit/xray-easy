import type { Theme } from './models'

const themeStorageKey = 'xray-easy-theme'

/**
 * Read the saved theme or fall back to the browser color preference.
 * @returns The selected light or dark theme.
 */
export function readTheme(): Theme {
  if (typeof window === 'undefined') return 'light'
  const stored = window.localStorage.getItem(themeStorageKey)
  if (stored === 'light' || stored === 'dark') return stored
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- Some embedded browser contexts omit matchMedia despite DOM typings.
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

/**
 * Apply the selected theme to the document and save it in browser storage.
 * @param theme - The theme to activate and persist.
 */
export function persistTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme
  window.localStorage.setItem(themeStorageKey, theme)
}

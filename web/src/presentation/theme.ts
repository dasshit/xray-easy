import type { Theme } from './models'

const themeStorageKey = 'xray-easy-theme'

export function readTheme(): Theme {
  if (typeof window === 'undefined') return 'light'
  const stored = window.localStorage.getItem(themeStorageKey)
  if (stored === 'light' || stored === 'dark') return stored
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- Some embedded browser contexts omit matchMedia despite DOM typings.
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

export function persistTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme
  window.localStorage.setItem(themeStorageKey, theme)
}

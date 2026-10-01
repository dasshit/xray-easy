import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { formatBytes, formatRate, formatTimestamp } from './format'
import { persistLanguage, readLanguage, useI18n } from './i18n'
import { persistTheme, readTheme } from './theme'
import { translations } from './i18n/messages'

describe('browser preferences', () => {
  beforeEach(() => {
    window.localStorage.clear()
    vi.stubGlobal('matchMedia', vi.fn(() => ({ matches: false })))
  })

  afterEach(() => vi.unstubAllGlobals())

  it('prefers an explicitly saved theme and otherwise follows the system preference', () => {
    vi.stubGlobal('matchMedia', vi.fn(() => ({ matches: true })))
    expect(readTheme()).toBe('dark')

    window.localStorage.setItem('xray-easy-theme', 'light')
    expect(readTheme()).toBe('light')

    window.localStorage.setItem('xray-easy-theme', 'invalid')
    expect(readTheme()).toBe('dark')
  })

  it('uses light theme when matchMedia is unavailable', () => {
    vi.stubGlobal('matchMedia', undefined)
    expect(readTheme()).toBe('light')
  })

  it('persists the selected theme in the document and local storage', () => {
    persistTheme('dark')
    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(window.localStorage.getItem('xray-easy-theme')).toBe('dark')
  })

  it('uses saved language or derives Russian from the browser locale', () => {
    vi.stubGlobal('navigator', { language: 'ru-RU' })
    expect(readLanguage()).toBe('ru')

    vi.stubGlobal('navigator', { language: 'fr-FR' })
    expect(readLanguage()).toBe('en')

    window.localStorage.setItem('xray-easy-language', 'ru')
    expect(readLanguage()).toBe('ru')
    window.localStorage.setItem('xray-easy-language', 'invalid')
    expect(readLanguage()).toBe('en')
  })

  it('persists a manually selected language', () => {
    persistLanguage('ru')
    expect(window.localStorage.getItem('xray-easy-language')).toBe('ru')
  })

  it('changes the reactive language and translations together', () => {
    window.localStorage.setItem('xray-easy-language', 'en')
    const i18n = useI18n()
    expect(i18n.t().title).toBe('Xray-easy')
    i18n.toggleLanguage()
    expect(i18n.language.value).toBe('ru')
    expect(i18n.t().title).toBe('Xray-easy')
    expect(window.localStorage.getItem('xray-easy-language')).toBe('ru')
  })

  it('keeps translation keys aligned between supported languages', () => {
    expect(Object.keys(translations.ru).sort()).toEqual(Object.keys(translations.en).sort())
  })
})

describe('formatBytes', () => {
  it('formats zero, bytes, and unit boundaries', () => {
    expect(formatBytes(0)).toBe('0 B')
    expect(formatBytes(1)).toBe('1 B')
    expect(formatBytes(1023)).toBe('1023 B')
    expect(formatBytes(1024)).toBe('1.0 KB')
    expect(formatBytes(10 * 1024)).toBe('10 KB')
    expect(formatBytes(1.5 * 1024)).toBe('1.5 KB')
  })

  it('scales through TB and keeps larger values in the largest unit', () => {
    expect(formatBytes(1024 ** 3)).toBe('1.0 GB')
    expect(formatBytes(1024 ** 4)).toBe('1.0 TB')
    expect(formatBytes(2 * 1024 ** 5)).toBe('2048 TB')
  })
})

describe('formatRate', () => {
  it('formats sampled traffic in bytes per second and clamps negative values', () => {
    expect(formatRate(0)).toBe('0 B/s')
    expect(formatRate(1024)).toBe('1.0 KB/s')
    expect(formatRate(-5)).toBe('0 B/s')
  })
})

describe('formatTimestamp', () => {
  afterEach(() => vi.restoreAllMocks())

  it('returns empty text for a missing timestamp', () => {
    expect(formatTimestamp(undefined, 'en')).toBe('')
  })

  it.each([
    ['en', 'en-US'],
    ['ru', 'ru-RU'],
  ] as const)('formats a timestamp with the %s locale', (language, expectedLocale) => {
    const format = vi.spyOn(Date.prototype, 'toLocaleString').mockReturnValue('formatted date')
    expect(formatTimestamp('2026-09-28T12:00:00.000Z', language)).toBe('formatted date')
    expect(format).toHaveBeenCalledWith(expectedLocale)
  })
})

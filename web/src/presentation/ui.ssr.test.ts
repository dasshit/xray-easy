// @vitest-environment node

import { describe, expect, it } from 'vitest'
import { readLanguage } from './i18n'
import { readTheme } from './theme'

describe('server-side browser preference fallbacks', () => {
  it('uses light theme when there is no window', () => {
    expect(readTheme()).toBe('light')
  })

  it('defaults to English when there is no window', () => {
    expect(readLanguage()).toBe('en')
  })
})

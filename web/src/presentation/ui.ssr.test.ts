// @vitest-environment node

import { describe, expect, it } from 'vitest'
import { readLanguage, useI18n } from './i18n'
import { readTheme } from './theme'

describe('server-side browser preference fallbacks', () => {
  it('uses light theme when there is no window', () => {
    expect(readTheme()).toBe('light')
  })

  it('defaults to English when there is no window', () => {
    expect(readLanguage()).toBe('en')
  })

  it('creates reactive translations without trying to touch a server-side document', () => {
    const i18n = useI18n()
    expect(i18n.language.value).toBe('en')
    expect(i18n.t().title).toBe('Xray-easy')
  })
})

import { describe, expect, it } from 'vitest'
import { requireValue } from './requireValue'

describe('requireValue', () => {
  it('returns present values and rejects absent ones', () => {
    expect(requireValue('ready', 'status')).toBe('ready')
    expect(() => requireValue(null, 'status')).toThrow('status is unavailable')
    expect(() => requireValue(undefined, 'status')).toThrow('status is unavailable')
  })
})

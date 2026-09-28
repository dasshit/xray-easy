import { describe, expect, it } from 'vitest'
import { canEnableClient, clientActionFor, type Client } from './models'

function client(overrides: Partial<Client> = {}): Client {
  return {
    id: 'client-id',
    name: 'phone',
    enabled: true,
    revoked: false,
    online: false,
    uploadBytes: 0,
    downloadBytes: 0,
    ...overrides,
  }
}

describe('client lifecycle presentation rules', () => {
  it('offers disable for an enabled profile', () => {
    expect(clientActionFor(client())).toBe('disable')
    expect(canEnableClient(client())).toBe(false)
  })

  it('offers enable for a disabled, non-revoked profile', () => {
    const disabled = client({ enabled: false })
    expect(clientActionFor(disabled)).toBe('enable')
    expect(canEnableClient(disabled)).toBe(true)
  })

  it('does not offer lifecycle actions for a revoked profile', () => {
    const revoked = client({ enabled: false, revoked: true })
    expect(clientActionFor(revoked)).toBeNull()
    expect(canEnableClient(revoked)).toBe(false)
  })
})

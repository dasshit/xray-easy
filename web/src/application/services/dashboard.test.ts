import { describe, expect, it, vi } from 'vitest'
import type { XrayEasyGateway } from '../ports/xrayEasyGateway'
import { loadAuthenticatedDashboard, loadDiagnosticsSnapshot, loadNodeStatusSnapshot } from './dashboard'

type GatewayOverrides = { [Area in keyof XrayEasyGateway]?: Partial<XrayEasyGateway[Area]> }

function gateway(overrides: GatewayOverrides = {}): XrayEasyGateway {
  const defaults: XrayEasyGateway = {
    setup: { status: vi.fn(), initialize: vi.fn() },
    auth: {
      current: vi.fn(), login: vi.fn(), loginWithTOTP: vi.fn(), loginWithRecoveryCode: vi.fn(),
      logout: vi.fn(), logoutAll: vi.fn(), changePassword: vi.fn(), totpStatus: vi.fn().mockResolvedValue({ enabled: false, recoveryCodesRemaining: 0 }),
      beginTOTPSetup: vi.fn(), enableTOTP: vi.fn(), disableTOTP: vi.fn(),
    },
    clients: { list: vi.fn().mockResolvedValue([]), create: vi.fn(), profile: vi.fn(), setAction: vi.fn(), profileQrUrl: vi.fn(), profileJsonUrl: vi.fn() },
    settings: { get: vi.fn().mockResolvedValue({ publicHost: 'vpn.test' }), preview: vi.fn(), apply: vi.fn() },
    hysteria: {
      status: vi.fn(), uploadCertificate: vi.fn(), generateCertificate: vi.fn(), preview: vi.fn(), apply: vi.fn(),
    },
    backups: { create: vi.fn() },
    diagnostics: {
      status: vi.fn().mockResolvedValue({ state: 'running', restartCount: 1 }),
      logs: vi.fn().mockResolvedValue([]),
    },
    events: { connect: vi.fn() },
  }
  return {
    setup: { ...defaults.setup, ...overrides.setup },
    clients: { ...defaults.clients, ...overrides.clients },
    auth: { ...defaults.auth, ...overrides.auth },
    settings: { ...defaults.settings, ...overrides.settings },
    hysteria: { ...defaults.hysteria, ...overrides.hysteria },
    backups: { ...defaults.backups, ...overrides.backups },
    diagnostics: { ...defaults.diagnostics, ...overrides.diagnostics },
    events: defaults.events,
  }
}

describe('authenticated dashboard service', () => {
  it('loads dashboard resources together and merges sorted diagnostic entries', async () => {
    const api = gateway({
      clients: { list: vi.fn().mockResolvedValue([{ id: 'client-1' }]) },
      auth: { totpStatus: vi.fn().mockResolvedValue({ enabled: true, recoveryCodesRemaining: 2 }) },
      settings: { get: vi.fn().mockResolvedValue({ publicHost: 'vpn.example.test' }) },
      diagnostics: {
        status: vi.fn().mockResolvedValue({ state: 'running', restartCount: 3 }),
        logs: vi.fn().mockImplementation(component => Promise.resolve(component === 'xray'
          ? [{ at: '2026-09-28T12:00:02Z', component, level: 'error', message: 'second' }]
          : [{ at: '2026-09-28T12:00:01Z', component, level: 'warn', message: 'first' }])),
      },
    })

    await expect(loadAuthenticatedDashboard(api)).resolves.toEqual({
      clients: [{ id: 'client-1' }],
      totpStatus: { enabled: true, recoveryCodesRemaining: 2 },
      settings: { publicHost: 'vpn.example.test' },
      nodeStatus: { state: 'running', restartCount: 3 },
      diagnostics: [
        { at: '2026-09-28T12:00:01Z', component: 'app', level: 'warn', message: 'first' },
        { at: '2026-09-28T12:00:02Z', component: 'xray', level: 'error', message: 'second' },
      ],
    })
  })

  it('uses the unavailable status fallback and keeps logs when one source fails', async () => {
    const api = gateway({
      diagnostics: {
        status: vi.fn().mockRejectedValue(new Error('service unavailable')),
        logs: vi.fn().mockImplementation(component => component === 'app'
          ? Promise.reject(new Error('log unavailable'))
          : Promise.resolve([{ at: '2026-09-28T12:00:00Z', component, level: 'error', message: 'kept' }])),
      },
    })

    await expect(loadNodeStatusSnapshot(api)).resolves.toEqual({ state: 'unavailable', restartCount: 0 })
    await expect(loadDiagnosticsSnapshot(api)).resolves.toEqual([
      { at: '2026-09-28T12:00:00Z', component: 'xray', level: 'error', message: 'kept' },
    ])
  })

  it('caps the merged log feed at the most recent 100 events', async () => {
    const entries = Array.from({ length: 65 }, (_, index) => ({
      at: `2026-09-28T12:00:${String(index).padStart(2, '0')}Z`, component: 'xray', level: 'warn', message: `event-${index}`,
    }))
    const api = gateway({ diagnostics: { logs: vi.fn().mockResolvedValue(entries) } })

    const result = await loadDiagnosticsSnapshot(api)
    expect(result).toHaveLength(100)
    expect(result[0]?.message).toBe('event-15')
    expect(result.at(-1)?.message).toBe('event-64')
    expect(api.diagnostics.logs).toHaveBeenNthCalledWith(1, 'xray', 100)
    expect(api.diagnostics.logs).toHaveBeenNthCalledWith(2, 'app', 100)
  })
})

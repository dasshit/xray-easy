import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { XrayEasyGateway, XrayEventCallbacks } from './application/ports/xrayEasyGateway'
import type { ProfileDelivery } from './application/models'
import type { Client, Settings } from './domain/models'
import App from './App.vue'
import { xrayEasyGatewayKey } from './presentation/api'

const settings: Settings = {
  publicHost: 'vpn.example.test', publicPort: 443, vmessPublicPort: 9443,
  shadowsocksEnabled: true, shadowsocksPublicPort: 10443, shadowsocksMethod: '2022-blake3-aes-256-gcm', shadowsocksNetwork: 'tcp',
  trojanEnabled: true, trojanPublicPort: 11443, realityTarget: 'www.example.test:443', realitySni: 'www.example.test',
  clientFingerprint: 'chrome', logLevel: 'warning', protocol: 'vless', network: 'tcp', security: 'reality', flow: 'xtls-rprx-vision',
}

const clients: Client[] = [
  { id: 'vmess-id', name: 'vmess-phone', protocol: 'vmess', protocols: ['vmess'], vmess: { enabled: true, revoked: false }, enabled: true, revoked: false, online: false, uploadBytes: 0, downloadBytes: 0 },
  { id: 'ss-id', name: 'ss-tablet', protocol: 'shadowsocks', protocols: ['shadowsocks'], shadowsocks: { enabled: true, revoked: false }, enabled: true, revoked: false, online: false, uploadBytes: 0, downloadBytes: 0 },
  { id: 'trojan-id', name: 'trojan-laptop', protocol: 'trojan', protocols: ['trojan'], trojan: { enabled: true, revoked: false }, enabled: true, revoked: false, online: false, uploadBytes: 0, downloadBytes: 0 },
]

const profiles: Record<string, ProfileDelivery> = {
  'vmess-id': { clientId: 'vmess-id', protocol: 'vmess', vmessUri: 'vmess://profile', json: {} },
  'ss-id': { clientId: 'ss-id', protocol: 'shadowsocks', ssUri: 'ss://profile', json: {} },
  'trojan-id': { clientId: 'trojan-id', protocol: 'trojan', trojanUri: 'trojan://profile', json: {} },
}

function createGateway(callbacks: { events?: XrayEventCallbacks } = {}) {
  const gateway = {
    setup: { status: vi.fn().mockResolvedValue({ initialized: true, publicPort: 443 }), initialize: vi.fn() },
    auth: {
      current: vi.fn().mockResolvedValue({ username: 'admin' }), login: vi.fn(), loginWithTOTP: vi.fn(), loginWithRecoveryCode: vi.fn(), logout: vi.fn(), logoutAll: vi.fn(), changePassword: vi.fn(),
      totpStatus: vi.fn().mockResolvedValue({ enabled: false, recoveryCodesRemaining: 0 }), beginTOTPSetup: vi.fn(), enableTOTP: vi.fn(), disableTOTP: vi.fn(),
    },
    clients: {
      list: vi.fn().mockResolvedValue(clients), create: vi.fn(), profile: vi.fn((id: string) => {
        const profile = profiles[id]
        return profile ? Promise.resolve(profile) : Promise.reject(new Error(`No profile fixture for ${id}`))
      }), setAction: vi.fn(),
      profileQrUrl: vi.fn(() => '/qr'), profileAmneziaWGUrl: vi.fn(() => '/awg'), profileAmneziaWGQrUrl: vi.fn(() => '/awg-qr'), profileHysteriaQrUrl: vi.fn(() => '/hy-qr'),
      profileVMessQrUrl: vi.fn(() => '/vmess-qr'), profileShadowsocksQrUrl: vi.fn(() => '/ss-qr'), profileTrojanQrUrl: vi.fn(() => '/trojan-qr'), profileJsonUrl: vi.fn(() => '/json'),
    },
    settings: { get: vi.fn().mockResolvedValue(settings), preview: vi.fn(), apply: vi.fn() },
    hysteria: { status: vi.fn().mockResolvedValue({ enabled: true, state: 'on', host: 'vpn.example.test', udpPort: 443, tlsMode: 'custom', tlsServerName: 'vpn.example.test', udpIdleTimeout: 60, masqueradeType: 'off', insecureUri: false, certificate: { subject: 'vpn.example.test', issuer: 'issuer', dnsNames: ['vpn.example.test'], ipAddresses: [], notBefore: '', notAfter: '', fingerprint: 'fingerprint' } }), uploadCertificate: vi.fn(), generateCertificate: vi.fn(), preview: vi.fn(), apply: vi.fn() },
    amneziawg: { status: vi.fn().mockResolvedValue({ enabled: false, available: false, running: false }) },
    backups: { create: vi.fn() },
    diagnostics: { status: vi.fn().mockResolvedValue({ state: 'running', xrayVersion: '26.7.28', inboundTags: ['trojan-tls'] }), logs: vi.fn().mockResolvedValue([]) },
    events: { connect: vi.fn((events: XrayEventCallbacks) => { callbacks.events = events; return { close: vi.fn() } }) },
  }
  return gateway as unknown as XrayEasyGateway
}

describe('App profile delivery actions', () => {
  beforeEach(() => {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: vi.fn().mockResolvedValue(undefined) } })
  })

  it('loads authenticated dashboard data and copies each supported share URI', async () => {
    const callbacks: { events?: XrayEventCallbacks } = {}
    const gateway = createGateway(callbacks)
    const hysteriaSettingsStub = {
      template: '<button data-testid="hysteria-saved" @click="$emit(\'saved\')">saved</button>',
      emits: ['saved'],
    }
    const wrapper = mount(App, {
      global: { provide: { [xrayEasyGatewayKey as symbol]: gateway }, stubs: { HysteriaSettingsPanel: hysteriaSettingsStub } },
    })
    await flushPromises()

    expect(gateway.clients.list).toHaveBeenCalledOnce()
    expect(gateway.diagnostics.logs).toHaveBeenCalledWith('xray', 100)
    expect(callbacks.events).toBeDefined()

    for (const [index, uri] of ['vmess://profile', 'ss://profile', 'trojan://profile'].entries()) {
      const device = wrapper.findAll('.device-card')[index]
      if (!device) throw new Error(`No device card at index ${index}`)
      await device.find('.device-actions button').trigger('click')
      await flushPromises()
      await wrapper.get('.profile-modal .copy-button').trigger('click')
      await flushPromises()
      expect(navigator.clipboard.writeText).toHaveBeenLastCalledWith(uri)
      await wrapper.get('.profile-modal .icon-button').trigger('click')
    }

    await wrapper.get('[role="tab"][aria-selected="false"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('.settings-trojan-card .status-badge').text()).toBe('Running')
    await wrapper.get('[data-testid="hysteria-saved"]').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('Changes saved')

    callbacks.events?.onStats()
    callbacks.events?.onStatus()
    await flushPromises()
    expect(gateway.clients.list).toHaveBeenCalledTimes(2)
    expect(gateway.diagnostics.status).toHaveBeenCalledTimes(2)
    wrapper.unmount()
  })

  it('does not report Trojan as running when the runtime does not report its inbound', async () => {
    const gateway = createGateway()
    vi.mocked(gateway.diagnostics.status).mockResolvedValue({ state: 'running', inboundTags: ['vless-reality'] })
    const wrapper = mount(App, {
      global: {
        provide: { [xrayEasyGatewayKey as symbol]: gateway },
        stubs: { HysteriaSettingsPanel: { template: '<div />' } },
      },
    })
    await flushPromises()
    const settingsTab = wrapper.findAll('[role="tab"]')[1]
    if (!settingsTab) throw new Error('Settings tab was not rendered')
    await settingsTab.trigger('click')
    await flushPromises()
    expect(wrapper.get('.settings-trojan-card .status-badge').text()).toBe('Unavailable')
    wrapper.unmount()
  })
})

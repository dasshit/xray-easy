import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { XrayEasyGateway, XrayEventCallbacks } from './application/ports/xrayEasyGateway'
import type { ProfileDelivery } from './application/models'
import type { Client, Settings } from './domain/models'
import App from './App.vue'
import { xrayEasyGatewayKey } from './presentation/api'
import { APIError } from './application/errors'

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
  { id: 'hysteria-id', name: 'hysteria-phone', protocol: 'hysteria2', protocols: ['hysteria2'], hysteria2: { enabled: true, revoked: false }, enabled: true, revoked: false, online: false, uploadBytes: 0, downloadBytes: 0 },
]

const profiles: Record<string, ProfileDelivery> = {
  'hysteria-id': { clientId: 'hysteria-id', protocol: 'hysteria2', hysteriaUri: 'hysteria2://profile' },
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
      list: vi.fn().mockResolvedValue([...clients]), create: vi.fn(), profile: vi.fn((id: string) => {
        const profile = profiles[id]
        return profile ? Promise.resolve(profile) : Promise.reject(new Error(`No profile fixture for ${id}`))
      }), setAction: vi.fn(), setExpiry: vi.fn(),
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

    vi.useFakeTimers()
    for (const [index, uri] of ['vmess://profile', 'ss://profile', 'trojan://profile'].entries()) {
      const device = wrapper.findAll('.device-card')[index]
      if (!device) throw new Error(`No device card at index ${index}`)
      const profileButton = device.findAll('.device-actions button').find(button => button.text() === 'Profile')
      if (!profileButton) throw new Error('Profile action was not rendered')
      await profileButton.trigger('click')
      await flushPromises()
      await wrapper.get('.profile-modal .copy-button').trigger('click')
      await flushPromises()
      expect(navigator.clipboard.writeText).toHaveBeenLastCalledWith(uri)
      expect(wrapper.get('.profile-modal .copy-button').text()).toContain('Copied')
      await vi.advanceTimersByTimeAsync(2200)
      expect(wrapper.get('.profile-modal .copy-button').text()).not.toContain('Copied')
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
    vi.useRealTimers()
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

  it('tracks the pointer highlight on glass surfaces and clears it when needed', async () => {
    const gateway = createGateway()
    const attachPoint = document.createElement('div')
    document.body.append(attachPoint)
    const wrapper = mount(App, {
      attachTo: attachPoint,
      global: { provide: { [xrayEasyGatewayKey as symbol]: gateway }, stubs: { HysteriaSettingsPanel: { template: '<div />' } } },
    })
    await flushPromises()

    const button = wrapper.get('.theme-toggle')
    const buttonElement = button.element as HTMLButtonElement
    vi.spyOn(button.element, 'getBoundingClientRect').mockReturnValue(new DOMRect(10, 20, 100, 40))
    const dispatchPointerMove = (target: EventTarget, pointerType = 'mouse', clientX = 60, clientY = 40) => {
      const event = new MouseEvent('pointermove', { bubbles: true, clientX, clientY })
      Object.defineProperty(event, 'pointerType', { value: pointerType })
      target.dispatchEvent(event)
    }

    window.dispatchEvent(new Event('pointermove'))
    dispatchPointerMove(buttonElement)
    expect(buttonElement.style.getPropertyValue('--glass-pointer-x')).toBe('50%')
    expect(buttonElement.style.getPropertyValue('--glass-pointer-y')).toBe('50%')

    window.dispatchEvent(new Event('pointermove'))
    expect(buttonElement.style.getPropertyValue('--glass-pointer-x')).toBe('')
    expect(buttonElement.style.getPropertyValue('--glass-pointer-y')).toBe('')

    dispatchPointerMove(buttonElement, 'touch')
    expect(buttonElement.style.getPropertyValue('--glass-pointer-x')).toBe('')
    dispatchPointerMove(buttonElement)
    dispatchPointerMove(wrapper.get('.brand-copy').element)
    expect(buttonElement.style.getPropertyValue('--glass-pointer-x')).toBe('')

    dispatchPointerMove(buttonElement)
    buttonElement.disabled = true
    dispatchPointerMove(buttonElement)
    expect(buttonElement.style.getPropertyValue('--glass-pointer-y')).toBe('')
    buttonElement.disabled = false

    await wrapper.get('.section-heading button').trigger('click')
    await flushPromises()
    const modal = wrapper.get('.modal')
    const modalElement = modal.element as HTMLElement
    vi.spyOn(modalElement, 'getBoundingClientRect').mockReturnValue(new DOMRect(30, 40, 200, 100))
    dispatchPointerMove(wrapper.get('.modal h2').element, 'mouse', 80, 90)
    expect(modalElement.style.getPropertyValue('--glass-pointer-x')).toBe('25%')
    expect(modalElement.style.getPropertyValue('--glass-pointer-y')).toBe('50%')

    wrapper.unmount()
    attachPoint.remove()
    expect(modalElement.style.getPropertyValue('--glass-pointer-x')).toBe('')
    expect(modalElement.style.getPropertyValue('--glass-pointer-y')).toBe('')

    const idleWrapper = mount(App, {
      global: { provide: { [xrayEasyGatewayKey as symbol]: createGateway() }, stubs: { HysteriaSettingsPanel: { template: '<div />' } } },
    })
    await flushPromises()
    idleWrapper.unmount()
  })

  it('reports clipboard failures for each share URI and resets copied notices on time', async () => {
    const gateway = createGateway()
    const clipboard = vi.fn().mockRejectedValue(new Error('Clipboard denied'))
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: clipboard } })
    const wrapper = mount(App, {
      global: { provide: { [xrayEasyGatewayKey as symbol]: gateway }, stubs: { HysteriaSettingsPanel: { template: '<div />' } } },
    })
    await flushPromises()

    for (const [name, expected] of [
      ['hysteria-phone', 'hysteria2://profile'], ['vmess-phone', 'vmess://profile'],
      ['ss-tablet', 'ss://profile'], ['trojan-laptop', 'trojan://profile'],
    ] as const) {
      const device = wrapper.findAll('.device-card').find(item => item.text().includes(name))
      if (!device) throw new Error(`No card for ${expected}`)
      const profileButton = device.findAll('.device-actions button').find(button => button.text() === 'Profile')
      if (!profileButton) throw new Error('Profile action was not rendered')
      await profileButton.trigger('click')
      await flushPromises()
      await wrapper.get('.profile-modal .copy-button').trigger('click')
      await flushPromises()
      expect(wrapper.get('[role="alert"]').text()).toContain('Clipboard denied')
      expect(clipboard).toHaveBeenLastCalledWith(expected)
      await wrapper.get('.profile-modal .icon-button').trigger('click')
    }

    wrapper.unmount()
  })

  it('requires an application gateway to render', () => {
    expect(() => mount(App)).toThrow('XrayEasyGateway was not provided')
  })

  it('localizes an invalid API response error in the selected language', async () => {
    const previousLanguage = localStorage.getItem('xray-easy-language')
    localStorage.setItem('xray-easy-language', 'ru')
    const gateway = createGateway()
    vi.mocked(gateway.setup.status).mockRejectedValue(new APIError('The server returned an invalid response', 'invalid_response'))
    const wrapper = mount(App, { global: { provide: { [xrayEasyGatewayKey as symbol]: gateway } } })

    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toBe('Сервер вернул ответ в неверном формате.')

    wrapper.unmount()
    if (previousLanguage === null) localStorage.removeItem('xray-easy-language')
    else localStorage.setItem('xray-easy-language', previousLanguage)
  })

  it('supports keyboard navigation and ARIA relationships for dashboard tabs', async () => {
    const gateway = createGateway()
    const wrapper = mount(App, {
      global: {
        provide: { [xrayEasyGatewayKey as symbol]: gateway },
        stubs: { HysteriaSettingsPanel: { template: '<div />' } },
      },
    })
    await flushPromises()

    const mainTabs = wrapper.findAll('[role="tablist"]')[0]
    if (!mainTabs) throw new Error('The dashboard tablist was not rendered')
    const mainButtons = mainTabs.findAll('[role="tab"]')
    await mainButtons[0]?.trigger('keydown', { key: 'ArrowRight' })
    expect(mainButtons[1]?.attributes('aria-selected')).toBe('true')
    expect(wrapper.get('#dashboard-panel').attributes('aria-labelledby')).toBe('section-tab-settings')
    expect(mainButtons[0]?.attributes('tabindex')).toBe('-1')
    expect(mainButtons[1]?.attributes('tabindex')).toBe('0')

    await mainButtons[1]?.trigger('keydown', { key: 'Home' })
    expect(mainButtons[0]?.attributes('aria-selected')).toBe('true')
    await mainButtons[0]?.trigger('keydown', { key: 'End' })
    expect(mainButtons[3]?.attributes('aria-selected')).toBe('true')
    await mainButtons[2]?.trigger('click')

    const diagnosticTabs = wrapper.get('.diagnostics-tabs')
    const xrayTab = diagnosticTabs.get('[data-testid="diagnostics-tab-xray"]')
    await xrayTab.trigger('keydown', { key: 'ArrowRight' })
    expect(diagnosticTabs.get('[data-testid="diagnostics-tab-awg"]').attributes('aria-selected')).toBe('true')
    expect(diagnosticTabs.get('[data-testid="diagnostics-tab-awg"]').attributes('tabindex')).toBe('0')

    wrapper.unmount()
  })

  it('does not open a duplicate event stream when startup authentication finishes late', async () => {
    let finishCurrent!: (admin: { username: string }) => void
    const startupCurrent = new Promise<{ username: string }>(resolve => { finishCurrent = resolve })
    const gateway = createGateway()
    vi.mocked(gateway.auth.current).mockReturnValue(startupCurrent)
    vi.mocked(gateway.auth.login).mockResolvedValue({ username: 'admin' })
    const wrapper = mount(App, {
      global: { provide: { [xrayEasyGatewayKey as symbol]: gateway }, stubs: { HysteriaSettingsPanel: { template: '<div />' } } },
    })
    await flushPromises()
    const form = wrapper.get('form.auth-card')
    await form.get('input[autocomplete="current-password"]').setValue('password')
    await form.trigger('submit')
    await flushPromises()
    expect(gateway.events.connect).toHaveBeenCalledOnce()

    finishCurrent({ username: 'admin' })
    await flushPromises()
    expect(gateway.events.connect).toHaveBeenCalledOnce()
    wrapper.unmount()
  })

  it('ignores queued event callbacks after signing out', async () => {
    const callbacks: { events?: XrayEventCallbacks } = {}
    const gateway = createGateway(callbacks)
    const wrapper = mount(App, {
      global: { provide: { [xrayEasyGatewayKey as symbol]: gateway }, stubs: { HysteriaSettingsPanel: { template: '<div />' } } },
    })
    await flushPromises()
    await wrapper.get('.topbar-logout').trigger('click')
    await flushPromises()
    const listCalls = vi.mocked(gateway.clients.list).mock.calls.length
    const statusCalls = vi.mocked(gateway.diagnostics.status).mock.calls.length
    callbacks.events?.onStats()
    callbacks.events?.onStatus()
    callbacks.events?.onError()
    await flushPromises()

    expect(gateway.clients.list).toHaveBeenCalledTimes(listCalls)
    expect(gateway.diagnostics.status).toHaveBeenCalledTimes(statusCalls)
    expect(wrapper.find('form.auth-card').exists()).toBe(true)
    wrapper.unmount()
  })

  it('keeps the typed login name if another request ends the session during password change', async () => {
    const gateway = createGateway()
    let finishPasswordChange!: () => void
    const passwordChange = new Promise<void>(resolve => { finishPasswordChange = resolve })
    vi.mocked(gateway.auth.changePassword).mockReturnValue(passwordChange)
    const wrapper = mount(App, {
      global: { provide: { [xrayEasyGatewayKey as symbol]: gateway }, stubs: { HysteriaSettingsPanel: { template: '<div />' } } },
    })
    await flushPromises()
    await wrapper.findAll('[role="tab"]').find(tab => tab.text() === 'Security')?.trigger('click')
    await flushPromises()
    const passwordForm = wrapper.find('.security-card form')
    if (!passwordForm.exists()) throw new Error('Expected the administrator password form')
    const inputs = passwordForm.findAll('input')
    await inputs[0]?.setValue('current-password')
    await inputs[1]?.setValue('a-long-new-password')
    await inputs[2]?.setValue('a-long-new-password')
    const changeRequest = passwordForm.trigger('submit')

    await wrapper.get('.topbar-logout').trigger('click')
    await flushPromises()
    await wrapper.get('form.auth-card input[autocomplete="username"]').setValue('typed-while-signing-out')
    finishPasswordChange()
    await changeRequest
    await flushPromises()

    expect((wrapper.get('form.auth-card input[autocomplete="username"]').element as HTMLInputElement).value).toBe('typed-while-signing-out')
    wrapper.unmount()
  })

  it('reports a gateway failure while changing the administrator password', async () => {
    const gateway = createGateway()
    vi.mocked(gateway.auth.changePassword).mockRejectedValue(new Error('Password update failed'))
    const wrapper = mount(App, {
      global: { provide: { [xrayEasyGatewayKey as symbol]: gateway }, stubs: { HysteriaSettingsPanel: { template: '<div />' } } },
    })
    await flushPromises()
    await wrapper.findAll('[role="tab"]').find(tab => tab.text() === 'Security')?.trigger('click')
    await flushPromises()
    const form = wrapper.get('.security-card form')
    const inputs = form.findAll('input')
    await inputs[0]?.setValue('current-password')
    await inputs[1]?.setValue('a-long-new-password')
    await inputs[2]?.setValue('a-long-new-password')
    await form.trigger('submit')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('Password update failed')
    wrapper.unmount()
  })

  it('reports a gateway failure while starting TOTP setup', async () => {
    const gateway = createGateway()
    vi.mocked(gateway.auth.beginTOTPSetup).mockRejectedValue(new Error('TOTP setup failed'))
    const wrapper = mount(App, {
      global: { provide: { [xrayEasyGatewayKey as symbol]: gateway }, stubs: { HysteriaSettingsPanel: { template: '<div />' } } },
    })
    await flushPromises()
    await wrapper.findAll('[role="tab"]').find(tab => tab.text() === 'Security')?.trigger('click')
    await flushPromises()
    const totpCard = wrapper.findAll('.security-card').find(card => card.text().includes('Two-factor authentication'))
    const enable = totpCard?.findAll('button').find(button => button.text() === 'Enable TOTP')
    if (!enable) throw new Error('Expected the TOTP setup button')
    await enable.trigger('click')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('TOTP setup failed')
    wrapper.unmount()
  })

  it('removes a profile when the lifecycle response has no updated profile', async () => {
    const gateway = createGateway()
    const client = clients[0]
    if (!client) throw new Error('Expected a profile fixture')
    vi.mocked(gateway.clients.setAction).mockResolvedValue(undefined)
    const wrapper = mount(App, {
      global: { provide: { [xrayEasyGatewayKey as symbol]: gateway }, stubs: { HysteriaSettingsPanel: { template: '<div />' } } },
    })
    await flushPromises()
    const row = wrapper.findAll('.device-card').find(item => item.text().includes(client.name))
    if (!row) throw new Error('Expected the profile fixture row')
    await row.findAll('button').find(button => button.text() === 'Disable')?.trigger('click')
    await wrapper.findAll('[role="dialog"] button').find(button => button.text() === 'Disable')?.trigger('click')
    await flushPromises()
    expect(wrapper.findAll('.device-card').some(item => item.text().includes(client.name))).toBe(false)
    wrapper.unmount()
  })

  it('saves an expiry when the profile disappears before the request returns', async () => {
    const callbacks: { events?: XrayEventCallbacks } = {}
    const gateway = createGateway(callbacks)
    const client = clients[0]
    if (!client) throw new Error('Expected a profile fixture')
    let finishExpiry!: (updated: Client) => void
    const settingExpiry = new Promise<Client>(resolve => { finishExpiry = resolve })
    vi.mocked(gateway.clients.setExpiry).mockReturnValue(settingExpiry)
    const wrapper = mount(App, {
      global: { provide: { [xrayEasyGatewayKey as symbol]: gateway }, stubs: { HysteriaSettingsPanel: { template: '<div />' } } },
    })
    await flushPromises()
    const row = wrapper.findAll('.device-card').find(item => item.text().includes(client.name))
    if (!row) throw new Error('Expected the profile fixture row')
    await row.find('.expiry-button').trigger('click')
    const pendingSave = wrapper.get('[role="dialog"] form').trigger('submit')

    vi.mocked(gateway.clients.list).mockResolvedValue([])
    callbacks.events?.onStats()
    await flushPromises()
    finishExpiry({ ...client, expiresAt: '2099-02-03T12:00:00Z' })
    await pendingSave
    await flushPromises()

    expect(wrapper.findAll('.device-card')).toHaveLength(0)
    expect(wrapper.find('[role="dialog"]').exists()).toBe(false)
    wrapper.unmount()
  })

  it('does not reinsert a profile when a lifecycle response arrives after its row disappears', async () => {
    const callbacks: { events?: XrayEventCallbacks } = {}
    const gateway = createGateway(callbacks)
    const client = clients[0]
    if (!client) throw new Error('Expected a profile fixture')
    let finishAction!: (updated: Client) => void
    const updating = new Promise<Client>(resolve => { finishAction = resolve })
    vi.mocked(gateway.clients.setAction).mockReturnValue(updating)
    const wrapper = mount(App, {
      global: { provide: { [xrayEasyGatewayKey as symbol]: gateway }, stubs: { HysteriaSettingsPanel: { template: '<div />' } } },
    })
    await flushPromises()
    const row = wrapper.findAll('.device-card').find(item => item.text().includes(client.name))
    if (!row) throw new Error('Expected the profile fixture row')
    await row.findAll('button').find(button => button.text() === 'Disable')?.trigger('click')
    const actionDialog = wrapper.get('[role="dialog"]')
    const confirm = actionDialog.findAll('button').find(button => button.text() === 'Disable')
    if (!confirm) throw new Error('Expected the disable confirmation button')
    const pendingAction = confirm.trigger('click')

    vi.mocked(gateway.clients.list).mockResolvedValue([])
    callbacks.events?.onStats()
    await flushPromises()
    finishAction({ ...client, enabled: false })
    await pendingAction
    await flushPromises()

    expect(wrapper.findAll('.device-card')).toHaveLength(0)
    wrapper.unmount()
  })

  it('skips the diagnostic refresh delay when requests already take longer than the minimum', async () => {
    const gateway = createGateway()
    let finishStatus!: (status: { state: string; inboundTags: string[] }) => void
    const delayedStatus = new Promise<{ state: string; inboundTags: string[] }>(resolve => { finishStatus = resolve })
    const wrapper = mount(App, {
      global: { provide: { [xrayEasyGatewayKey as symbol]: gateway }, stubs: { HysteriaSettingsPanel: { template: '<div />' } } },
    })
    await flushPromises()
    await wrapper.findAll('[role="tab"]').find(tab => tab.text() === 'Diagnostics')?.trigger('click')
    expect(gateway.diagnostics.status).toHaveBeenCalledOnce()
    vi.mocked(gateway.diagnostics.status).mockReturnValueOnce(delayedStatus)
    vi.useFakeTimers()
    const refreshButton = wrapper.get('[aria-label="Refresh diagnostics"]')
    expect((refreshButton.element as HTMLButtonElement).disabled).toBe(false)
    const refresh = refreshButton.trigger('click')
    await refresh
    expect(gateway.diagnostics.status).toHaveBeenCalledTimes(2)
    await vi.advanceTimersByTimeAsync(3_000)
    finishStatus({ state: 'running', inboundTags: [] })
    await flushPromises()
    expect(wrapper.get('[aria-label="Refresh diagnostics"] svg').classes()).not.toContain('spinning')
    vi.useRealTimers()
    wrapper.unmount()
  })

  it('safely ignores copy events when the selected profile has no share URI', async () => {
    const gateway = createGateway()
    const client: Client = {
      id: 'empty-uri', name: 'empty-uri', protocol: 'vless', protocols: ['vless'],
      vless: { enabled: true, revoked: false }, enabled: true, revoked: false, online: false, uploadBytes: 0, downloadBytes: 0,
    }
    const hysteriaClient = clients[3]
    if (!hysteriaClient) throw new Error('Expected a Hysteria profile fixture')
    vi.mocked(gateway.clients.list).mockResolvedValue([client, hysteriaClient])
    vi.mocked(gateway.clients.profile).mockResolvedValueOnce({ clientId: client.id, protocol: 'vless', uri: '', json: {} })
    const wrapper = mount(App, {
      global: {
        provide: { [xrayEasyGatewayKey as symbol]: gateway },
        stubs: {
          HysteriaSettingsPanel: { template: '<div />' },
          ProfileDeliveryModal: {
            emits: ['copyVless', 'copyHysteria', 'copyVmess', 'copyShadowsocks', 'copyTrojan'],
            template: '<div><button @click="$emit(\'copyVless\')">VLESS</button><button @click="$emit(\'copyHysteria\')">Hysteria</button><button @click="$emit(\'copyVmess\')">VMess</button><button @click="$emit(\'copyShadowsocks\')">Shadowsocks</button><button @click="$emit(\'copyTrojan\')">Trojan</button></div>',
          },
        },
      },
    })
    await flushPromises()
    const profileButton = wrapper.findAll('.device-actions button').find(button => button.text() === 'Profile')
    if (!profileButton) throw new Error('Profile action was not rendered')
    await profileButton.trigger('click')
    await flushPromises()
    for (const button of wrapper.findAll('button').filter(item => ['VLESS', 'Hysteria', 'VMess', 'Shadowsocks', 'Trojan'].includes(item.text()))) {
      await button.trigger('click')
    }
    const hysteriaRow = wrapper.findAll('.device-card').find(row => row.text().includes(hysteriaClient.name))
    await hysteriaRow?.findAll('button').find(button => button.text() === 'Profile')?.trigger('click')
    await flushPromises()
    await wrapper.findAll('button').find(button => button.text() === 'VLESS')?.trigger('click')

    expect(navigator.clipboard.writeText).not.toHaveBeenCalled()
    expect(wrapper.find('[role="alert"]').exists()).toBe(false)
    wrapper.unmount()
  })

  it('keeps both profile and action dialogs open while a lifecycle request is pending', async () => {
    const gateway = createGateway()
    const client = clients[0]
    if (!client) throw new Error('Expected a profile fixture')
    let finishAction!: (updated: Client | undefined) => void
    const action = new Promise<Client | undefined>(resolve => { finishAction = resolve })
    vi.mocked(gateway.clients.setAction).mockReturnValue(action)
    const wrapper = mount(App, {
      global: { provide: { [xrayEasyGatewayKey as symbol]: gateway }, stubs: { HysteriaSettingsPanel: { template: '<div />' } } },
    })
    await flushPromises()
    const device = wrapper.findAll('.device-card').find(row => row.text().includes(client.name))
    if (!device) throw new Error('Expected the profile fixture row')
    await device.findAll('button').find(button => button.text() === 'Profile')?.trigger('click')
    await flushPromises()
    await device.findAll('button').find(button => button.text() === 'Disable')?.trigger('click')
    const actionDialog = wrapper.findAll('[role="dialog"]').find(dialog => dialog.text().includes('Confirm action'))
    if (!actionDialog) throw new Error('Expected the action confirmation')
    const confirm = actionDialog.findAll('button').find(button => button.text() === 'Disable')
    if (!confirm) throw new Error('Expected the disable confirmation button')
    const pendingRequest = confirm.trigger('click')

    await wrapper.get('.profile-modal .icon-button').trigger('click')
    await actionDialog.findAll('button').find(button => button.text() === 'Cancel')?.trigger('click')
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    await flushPromises()
    expect(wrapper.find('.profile-modal').exists()).toBe(true)
    expect(wrapper.find('[role="dialog"]').exists()).toBe(true)

    finishAction({ ...client, enabled: false })
    await pendingRequest
    await flushPromises()
    expect(wrapper.findAll('[role="dialog"]').some(dialog => dialog.text().includes('Confirm action'))).toBe(false)
    expect(wrapper.find('.profile-modal').exists()).toBe(true)
    await wrapper.get('.profile-modal .icon-button').trigger('click')
    wrapper.unmount()
  })

  it('keeps the create dialog open while profile creation is pending', async () => {
    const gateway = createGateway()
    let finishCreate!: (created: Client) => void
    const creating = new Promise<Client>(resolve => { finishCreate = resolve })
    const created: Client = {
      id: 'created-id', name: 'new-device', protocol: 'vless', protocols: ['vless'],
      vless: { enabled: true, revoked: false }, enabled: true, revoked: false, online: false, uploadBytes: 0, downloadBytes: 0,
    }
    vi.mocked(gateway.clients.create).mockReturnValue(creating)
    vi.mocked(gateway.clients.profile).mockResolvedValue({ clientId: created.id, protocol: 'vless', uri: 'vless://created', json: {} })
    const wrapper = mount(App, {
      global: { provide: { [xrayEasyGatewayKey as symbol]: gateway }, stubs: { HysteriaSettingsPanel: { template: '<div />' } } },
    })
    await flushPromises()
    await wrapper.findAll('button').find(button => button.text().includes('Create profile'))?.trigger('click')
    await wrapper.get('.modal input[autocomplete="off"]').setValue(created.name)
    const submission = wrapper.get('.modal form').trigger('submit')

    await wrapper.get('.modal .icon-button').trigger('click')
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    await flushPromises()
    expect(wrapper.find('[data-testid="profile-protocol"]').exists()).toBe(true)

    finishCreate(created)
    await submission
    await flushPromises()
    expect(wrapper.find('[data-testid="profile-protocol"]').exists()).toBe(false)
    expect(wrapper.find('.profile-modal').exists()).toBe(true)
    wrapper.unmount()
  })

  it('lets the administrator extend an expired profile before explicitly enabling it', async () => {
    const gateway = createGateway()
    const expiredClient: Client = {
      id: 'expired-vless', name: 'old-phone', protocol: 'vless', protocols: ['vless'],
      vless: { enabled: false, revoked: false }, enabled: false, revoked: false, expired: true,
      expirationPending: false, expiresAt: '2026-09-30T12:00:00Z', online: false, uploadBytes: 0, downloadBytes: 0,
    }
    vi.mocked(gateway.clients.list).mockResolvedValue([expiredClient])
    vi.mocked(gateway.clients.setExpiry).mockResolvedValue({ ...expiredClient, expiresAt: '2099-02-03T12:00:00Z', expired: false })
    const wrapper = mount(App, {
      global: {
        provide: { [xrayEasyGatewayKey as symbol]: gateway },
        stubs: { HysteriaSettingsPanel: { template: '<div />' } },
      },
    })
    await flushPromises()
    expect(wrapper.get('.status-badge').text()).toBe('expired')
    expect(wrapper.findAll('.device-actions button').map(button => button.text())).not.toContain('Enable')

    await wrapper.get('.expiry-button').trigger('click')
    await wrapper.get('[data-testid="expiry-custom"]').setValue('2099-02-03T12:00')
    await wrapper.get('.modal form').trigger('submit')
    await flushPromises()

    expect(gateway.clients.setExpiry).toHaveBeenCalledWith('expired-vless', new Date('2099-02-03T12:00').toISOString())
    expect(wrapper.get('.status-badge').text()).toBe('disabled')
    expect(wrapper.findAll('.device-actions button').map(button => button.text())).toContain('Enable')
    wrapper.unmount()
  })

})

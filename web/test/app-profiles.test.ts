import { describe, expect, it, vi } from 'vitest'
import type { Client } from '../src/domain/models'
import { clientDto, defaultHandler, flushPromises, hysteriaStatus, mountApp, openTab, sampleClient, type RequestRecord } from './appHarness'

type ButtonFinder = { text(): string; trigger(event: string): Promise<unknown> }
function findButton(wrapper: { findAll(selector: string): ButtonFinder[] }, label: string) {
  const button = wrapper.findAll('button').find(item => item.text().trim() === label)
  if (!button) throw new Error(`Button not found: ${label}`)
  return button
}

describe('profile list and creation', () => {
  it('shows the empty state and opens the create form', async () => {
    const { wrapper } = await mountApp(defaultHandler({ authenticated: true }))
    expect(wrapper.text()).toContain('No profiles yet')
    await findButton(wrapper, 'Create profile').trigger('click')
    expect(wrapper.get('[role="dialog"]').text()).toContain('Device name')
    const nameInput = wrapper.get('input.device-name-input')
    expect(nameInput.attributes('maxlength')).toBe('64')
    expect(document.activeElement).toBe(nameInput.element)
  })

  it('creates a profile with the selected fingerprint and opens its delivery view', async () => {
    const requests: RequestRecord[] = []
    const created = { ...sampleClient, id: 'new-id', name: 'work mac', fingerprint: 'safari' }
    const { wrapper } = await mountApp(request => {
      requests.push(request)
      if (request.method === 'POST' && request.url === '/api/clients') return { status: 201, body: clientDto(created) }
      return defaultHandler({ authenticated: true })(request)
    })

    await findButton(wrapper, 'Create profile').trigger('click')
    const dialog = wrapper.get('[role="dialog"]')
    await dialog.get('input.device-name-input').setValue('work mac')
    await dialog.get('[data-testid="profile-protocol"]').setValue('vless')
    await dialog.findAll('select')[1]?.setValue('safari')
    await dialog.get('form').trigger('submit')
    await flushPromises()

    expect(requests.find(request => request.url === '/api/clients' && request.method === 'POST')?.body).toEqual({
      name: 'work mac', protocol: 'vless', fingerprint: 'safari',
    })
    expect(wrapper.text()).toContain('Profile for work mac')
    expect(wrapper.get('.profile-modal img.qr').attributes('src')).toBe('/api/clients/new-id/profile?format=qr')
    expect((wrapper.get('.profile-modal textarea').element as HTMLTextAreaElement).value).toContain('vless://new-id@vpn.example.com:443')
    expect(wrapper.get('.profile-modal a.download-link').attributes('href')).toBe('/api/clients/new-id/profile?format=json')
    expect(wrapper.findAll('.device-card')).toHaveLength(1)
  })

  it('omits an empty fingerprint so the server uses its default', async () => {
    const requests: RequestRecord[] = []
    const { wrapper } = await mountApp(request => {
      requests.push(request)
      if (request.method === 'POST' && request.url === '/api/clients') return { status: 201, body: clientDto({ ...sampleClient, name: 'tablet' }) }
      return defaultHandler({ authenticated: true })(request)
    })
    await findButton(wrapper, 'Create profile').trigger('click')
    const dialog = wrapper.get('[role="dialog"]')
    await dialog.get('input.device-name-input').setValue('tablet')
    await dialog.get('form').trigger('submit')
    await flushPromises()
    expect(requests.find(request => request.url === '/api/clients' && request.method === 'POST')?.body).toEqual({ name: 'tablet', protocol: 'vless' })
    expect(wrapper.text()).toContain('Profile for tablet')
  })

  it('creates and delivers only the Hysteria 2 profile when that inbound is ready', async () => {
    const requests: RequestRecord[] = []
    const hysteriaClient: Client = {
      id: 'hysteria-device', name: 'travel-phone', protocol: 'hysteria2', protocols: ['hysteria2'],
      hysteria2: { enabled: true, revoked: false }, enabled: true, revoked: false, online: false, uploadBytes: 0, downloadBytes: 0,
    }
    const { wrapper } = await mountApp(request => {
      requests.push(request)
      if (request.url === '/api/transports/hysteria2') return { body: { ...hysteriaStatus, enabled: true, state: 'on' } }
      if (request.method === 'POST' && request.url === '/api/clients') return { status: 201, body: clientDto(hysteriaClient) }
      if (request.url === '/api/clients/hysteria-device/profile?format=uri') return {
        body: { client_id: hysteriaClient.id, protocol: 'hysteria2', hysteria_uri: 'hysteria2://custom-secret@vpn.example.com:443?insecure=1' },
      }
      return defaultHandler({ authenticated: true })(request)
    })

    await findButton(wrapper, 'Create profile').trigger('click')
    const dialog = wrapper.get('[role="dialog"]')
    await dialog.get('input.device-name-input').setValue('travel-phone')
    await dialog.get('[data-testid="profile-protocol"]').setValue('hysteria2')
    await dialog.get('details summary').trigger('click')
    await dialog.get('input[autocomplete="new-password"]').setValue('custom-secret')
    await dialog.get('form').trigger('submit')
    await flushPromises()

    expect(requests.find(request => request.method === 'POST' && request.url === '/api/clients')?.body).toEqual({
      name: 'travel-phone', protocol: 'hysteria2', auth: 'custom-secret',
    })
    expect(wrapper.get('.device-card').text()).toContain('Hysteria 2')
    const profileDialog = wrapper.get('.profile-modal')
    expect((profileDialog.get('textarea').element as HTMLTextAreaElement).value).toBe('hysteria2://custom-secret@vpn.example.com:443?insecure=1')
    expect(profileDialog.get('img.qr').attributes('src')).toBe('/api/clients/hysteria-device/profile?format=hysteria-qr')
    expect(profileDialog.find('a.download-link').exists()).toBe(false)
    expect(profileDialog.text()).not.toContain('VLESS URI')
    await profileDialog.get('.copy-button').trigger('click')
    await flushPromises()
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('hysteria2://custom-secret@vpn.example.com:443?insecure=1')
    expect(wrapper.get('[role="status"]').text()).toContain('Profile link copied')
  })

  it('creates and manages AmneziaWG inside the shared profile screen', async () => {
    const requests: RequestRecord[] = []
    const awgClient: Client = {
      id: 'awg:iphone', name: 'iphone', protocol: 'amneziawg', protocols: ['amneziawg'],
      enabled: true, revoked: false, online: true, lastSeen: '2026-09-30T12:00:00Z',
      uploadBytes: 4096, downloadBytes: 8192, sourceIPs: ['203.0.113.9'],
      uploadBytesPerSecond: 12.5, downloadBytesPerSecond: 1024,
    }
    const awgStatus = {
      enabled: true, available: true, running: true, public_key: 'server-public-key',
      public_host: 'vpn.example.test', public_port: 1234, listen_port: 1234,
      peer_count: 1, ipv4_network: '10.88.0.0/24', ipv6_network: 'fd88:88:88::/64', service_version: 'prototype-v1',
    }
    const { wrapper } = await mountApp(request => {
      requests.push(request)
      if (request.method === 'GET' && request.url === '/api/clients') return { body: [] }
      if (request.url === '/api/transports/amneziawg') return { body: awgStatus }
      if (request.method === 'POST' && request.url === '/api/clients') return { status: 201, body: clientDto(awgClient) }
      if (request.url === '/api/clients/awg%3Aiphone/profile?format=uri') return { body: { client_id: awgClient.id, protocol: 'amneziawg', name: 'iphone' } }
      if (request.method === 'POST' && request.url === '/api/clients/awg%3Aiphone/revoke') return { body: { removed: true, name: 'iphone' } }
      return defaultHandler({ authenticated: true })(request)
    })

    expect(wrapper.findAll('[role="tab"]').map(tab => tab.text())).not.toContain('AmneziaWG')
    await findButton(wrapper, 'Create profile').trigger('click')
    const createDialog = wrapper.get('[role="dialog"]')
    await createDialog.get('input.device-name-input').setValue('iphone')
    await createDialog.get('[data-testid="profile-protocol"]').setValue('amneziawg')
    await createDialog.get('form').trigger('submit')
    await flushPromises()

    expect(requests.find(request => request.method === 'POST' && request.url === '/api/clients')?.body).toEqual({ name: 'iphone', protocol: 'amneziawg' })
    expect(wrapper.get('.profile-modal img.qr').attributes('src')).toBe('/api/transports/amneziawg/peers/iphone/profile/qr')
    expect(wrapper.get('.profile-modal a.download-link').attributes('href')).toBe('/api/transports/amneziawg/peers/iphone/profile')
    await wrapper.get('.profile-modal .icon-button').trigger('click')

    const device = wrapper.get('.device-card')
    expect(device.text()).toContain('203.0.113.9')
    expect(device.text()).toContain('13 B/s')
    expect(device.text()).toContain('1.0 KB/s')
    expect(device.text()).toContain('4.0 KB')
    await openTab(wrapper, 'Settings')
    expect(wrapper.text()).toContain('vpn.example.test:1234/UDP')
    expect(wrapper.text()).toContain('10.88.0.0/24')
    await openTab(wrapper, 'Profiles')
    await findButton(wrapper, 'Revoke').trigger('click')
    const revokeDialog = wrapper.get('.modal-small')
    expect(revokeDialog.text()).toContain('Its saved profile will be deleted')
    await findButton(revokeDialog, 'Revoke').trigger('click')
    await flushPromises()
    expect(wrapper.findAll('.device-card')).toHaveLength(0)
    expect(requests.some(request => request.method === 'POST' && request.url === '/api/clients/awg%3Aiphone/revoke')).toBe(true)
  })

  it('keeps VLESS available when Hysteria status cannot be loaded and opens Settings from the notice', async () => {
    const { wrapper } = await mountApp(request => {
      if (request.url === '/api/transports/hysteria2') return { status: 503, body: { error: 'transport unavailable' } }
      return defaultHandler({ authenticated: true })(request)
    })
    await findButton(wrapper, 'Create profile').trigger('click')
    const dialog = wrapper.get('[role="dialog"]')
    expect((dialog.get('option[value="hysteria2"]').element as HTMLOptionElement).disabled).toBe(true)
    await dialog.findAll('button').find(button => button.text() === 'Open Hysteria 2 settings')?.trigger('click')
    await flushPromises()
    expect(wrapper.findAll('[role="dialog"]')).toHaveLength(0)
    expect(wrapper.find('[role="tab"][aria-selected="true"]').text()).toBe('Settings')
    expect(wrapper.get('[role="alert"]').text()).toContain('transport unavailable')
  })

  it('keeps the create dialog open and displays an error if creation fails', async () => {
    const { wrapper } = await mountApp(request => {
      if (request.method === 'POST' && request.url === '/api/clients') return { status: 400, body: { error: 'Invalid device name' } }
      return defaultHandler({ authenticated: true })(request)
    })
    await findButton(wrapper, 'Create profile').trigger('click')
    await wrapper.get('input.device-name-input').setValue('phone')
    await wrapper.get('[role="dialog"] form').trigger('submit')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('Invalid device name')
    expect(wrapper.get('[role="dialog"]').text()).toContain('Create profile')
    expect(wrapper.findAll('.device-card')).toHaveLength(0)
  })

  it('does not submit an empty or whitespace-only device name', async () => {
    const { wrapper, requests } = await mountApp(defaultHandler({ authenticated: true }))
    await findButton(wrapper, 'Create profile').trigger('click')
    const dialog = wrapper.get('[role="dialog"]')
    expect((dialog.get('button[type="submit"]').element as HTMLButtonElement).disabled).toBe(true)
    await dialog.get('input.device-name-input').setValue('   ')
    expect((dialog.get('button[type="submit"]').element as HTMLButtonElement).disabled).toBe(true)
    expect(requests.some(request => request.method === 'POST' && request.url === '/api/clients')).toBe(false)
  })

  it('closes the create modal when its backdrop is clicked', async () => {
    const { wrapper } = await mountApp(defaultHandler({ authenticated: true }))
    await findButton(wrapper, 'Create profile').trigger('click')
    await wrapper.get('.modal-backdrop').trigger('click')
    expect(wrapper.findAll('[role="dialog"]')).toHaveLength(0)
  })
})

describe('profile delivery', () => {
  it('shows the QR, VLESS URI, and JSON download for an existing profile', async () => {
    const { wrapper, requests } = await mountApp(defaultHandler({ authenticated: true, clients: [sampleClient] }))
    await findButton(wrapper, 'Profile').trigger('click')
    await flushPromises()
    expect(requests.some(request => request.url === `/api/clients/${sampleClient.id}/profile?format=uri`)).toBe(true)
    const dialog = wrapper.get('.profile-modal')
    expect(dialog.text()).toContain('Profile for phone')
    expect(dialog.get('img.qr').attributes('src')).toBe(`/api/clients/${sampleClient.id}/profile?format=qr`)
    expect(dialog.get('textarea').element.value).toContain(`vless://${sampleClient.id}@vpn.example.com`)
    expect(dialog.get('a.download-link').attributes('href')).toBe(`/api/clients/${sampleClient.id}/profile?format=json`)
  })

  it('can reopen the profile after closing its delivery dialog', async () => {
    const { wrapper, requests } = await mountApp(defaultHandler({ authenticated: true, clients: [sampleClient] }))
    await findButton(wrapper, 'Profile').trigger('click')
    await flushPromises()
    await wrapper.get('.profile-modal .icon-button').trigger('click')
    expect(wrapper.findAll('.profile-modal')).toHaveLength(0)
    await findButton(wrapper, 'Profile').trigger('click')
    await flushPromises()
    expect(wrapper.findAll('.profile-modal')).toHaveLength(1)
    expect(requests.filter(request => request.url.endsWith('/profile?format=uri'))).toHaveLength(2)
  })

  it('copies the VLESS URI and reports success', async () => {
    const { wrapper } = await mountApp(defaultHandler({ authenticated: true, clients: [sampleClient] }))
    await findButton(wrapper, 'Profile').trigger('click')
    await flushPromises()
    await wrapper.get('.profile-modal .copy-button').trigger('click')
    await flushPromises()
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(`vless://${sampleClient.id}@vpn.example.com:443?security=reality#phone`)
    expect(wrapper.text()).toContain('Copied')
    expect(wrapper.get('[role="status"]').text()).toContain('Profile link copied')
  })

  it('shows an error if clipboard access fails', async () => {
    const { wrapper } = await mountApp(defaultHandler({ authenticated: true, clients: [sampleClient] }))
    vi.stubGlobal('navigator', { language: 'en-US', clipboard: { writeText: vi.fn().mockRejectedValue(new Error('Clipboard unavailable')) } })
    await findButton(wrapper, 'Profile').trigger('click')
    await flushPromises()
    await wrapper.get('.profile-modal .copy-button').trigger('click')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('Clipboard unavailable')
  })
})

describe('profile lifecycle confirmation', () => {
  it.each([
    { initial: { ...sampleClient, enabled: true }, action: 'disable', label: 'Disable', expectedEnabled: false },
    { initial: { ...sampleClient, enabled: false }, action: 'enable', label: 'Enable', expectedEnabled: true },
    { initial: { ...sampleClient, enabled: true }, action: 'revoke', label: 'Delete profile', expectedEnabled: false, revoked: true },
  ] as Array<{ initial: Client; action: 'disable' | 'enable' | 'revoke'; label: string; expectedEnabled: boolean; revoked?: boolean }>)('confirms $action and applies the returned profile state', async scenario => {
    const requests: RequestRecord[] = []
    const updated = { ...scenario.initial, enabled: scenario.expectedEnabled, revoked: scenario.revoked ?? false }
    const { wrapper } = await mountApp(request => {
      requests.push(request)
      if (request.url === `/api/clients/${sampleClient.id}/${scenario.action}`) return { body: clientDto(updated) }
      return defaultHandler({ authenticated: true, clients: [scenario.initial] })(request)
    })
    await findButton(wrapper.get('.device-card'), scenario.label).trigger('click')
    await flushPromises()
    expect(wrapper.get('[role="dialog"]').text()).toContain('Confirm action')
    if (scenario.revoked === true) expect(wrapper.get('[role="dialog"]').text()).toContain('cannot be undone')
    await findButton(wrapper.get('[role="dialog"]'), scenario.label).trigger('click')
    await flushPromises()
    expect(requests.some(request => request.url === `/api/clients/${sampleClient.id}/${scenario.action}` && request.method === 'POST')).toBe(true)
    expect(wrapper.get('.device-card').text()).toContain(scenario.revoked === true ? 'revoked' : scenario.expectedEnabled ? 'enabled' : 'disabled')
    if (scenario.revoked === true) expect(wrapper.get('.device-card').findAll('button')).toHaveLength(0)
  })

  it('does not apply an action that was canceled', async () => {
    const { wrapper, requests } = await mountApp(defaultHandler({ authenticated: true, clients: [sampleClient] }))
    await findButton(wrapper.get('.device-card'), 'Disable').trigger('click')
    await findButton(wrapper.get('[role="dialog"]'), 'Cancel').trigger('click')
    expect(wrapper.findAll('[role="dialog"]')).toHaveLength(0)
    expect(requests.some(request => request.url.endsWith('/disable'))).toBe(false)
  })

  it('preserves the profile and confirmation if the lifecycle request fails', async () => {
    const { wrapper } = await mountApp(request => {
      if (request.url.endsWith('/disable')) return { status: 502, body: { error: 'Xray apply failed' } }
      return defaultHandler({ authenticated: true, clients: [sampleClient] })(request)
    })
    await findButton(wrapper.get('.device-card'), 'Disable').trigger('click')
    await findButton(wrapper.get('[role="dialog"]'), 'Disable').trigger('click')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('Xray apply failed')
    expect(wrapper.get('.device-card').text()).toContain('enabled')
    expect(wrapper.findAll('[role="dialog"]')).toHaveLength(1)
  })

  it('closes the active profile action dialog on Escape', async () => {
    const { wrapper } = await mountApp(defaultHandler({ authenticated: true, clients: [sampleClient] }))
    await findButton(wrapper.get('.device-card'), 'Disable').trigger('click')
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    await flushPromises()
    expect(wrapper.findAll('[role="dialog"]')).toHaveLength(0)
  })
})

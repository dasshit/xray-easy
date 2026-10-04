import { describe, expect, it, vi } from 'vitest'
import type { Client } from '../src/domain/models'
import { defaultHandler, flushPromises, mountApp, openTab, sampleClient, settings as settingsDto } from './appHarness'

describe('remaining dashboard states', () => {
  it('renders a legacy combined profile, copies both links, and displays a profile-load failure', async () => {
    const legacyClient: Client = {
      ...sampleClient,
      id: 'legacy-device',
      protocol: 'legacy_dual' as const,
      protocols: ['vless', 'hysteria2'],
      vless: { enabled: true, revoked: false },
      hysteria2: { enabled: false, revoked: false },
      sourceIPs: ['192.0.2.12'],
    }
    const brokenClient = { ...sampleClient, id: 'broken-device', name: 'broken-phone' }
    const rawFailureClient = { ...sampleClient, id: 'raw-failure', name: 'raw-failure-phone' }
    const revokedAccessClient: Client = {
      ...sampleClient, id: 'revoked-access', name: 'revoked-access-phone',
      vless: { enabled: false, revoked: true }, enabled: false, revoked: false,
    }
    const { wrapper } = await mountApp(request => {
      if (request.url === '/api/clients/legacy-device/profile?format=uri') return { body: {
        client_id: legacyClient.id, protocol: 'legacy_dual', uri: 'vless://legacy', hysteria_uri: 'hysteria2://legacy',
      } }
      if (request.url === '/api/clients/broken-device/profile?format=uri') throw new Error('profile store unavailable')
      if (request.url === '/api/clients/raw-failure/profile?format=uri') {
        // Exercise the UI fallback for consumers that reject with a non-Error value.
        // eslint-disable-next-line @typescript-eslint/only-throw-error
        throw 'connection lost'
      }
      return defaultHandler({ authenticated: true, clients: [legacyClient, brokenClient, rawFailureClient, revokedAccessClient] })(request)
    })

    const legacyRow = wrapper.findAll('.device-card').find(row => row.text().includes('Legacy · VLESS + Hysteria 2'))
    expect(legacyRow?.text()).toContain('VLESS: enabled · Hysteria 2: disabled')
    expect(legacyRow?.text()).toContain('192.0.2.12')
    await legacyRow?.findAll('button').find(button => button.text() === 'Profile')?.trigger('click')
    await flushPromises()
    expect(wrapper.get('.profile-modal').text()).toContain('Legacy · VLESS + Hysteria 2')
    expect(wrapper.findAll('.profile-modal .profile-delivery')).toHaveLength(2)
    vi.useFakeTimers()
    await wrapper.findAll('.profile-modal .copy-button')[0]?.trigger('click')
    expect(vi.mocked(navigator.clipboard.writeText)).toHaveBeenLastCalledWith('vless://legacy')
    await wrapper.findAll('.profile-modal .copy-button')[1]?.trigger('click')
    expect(vi.mocked(navigator.clipboard.writeText)).toHaveBeenLastCalledWith('hysteria2://legacy')
    await vi.advanceTimersByTimeAsync(2200)
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    await flushPromises()
    expect(wrapper.find('.profile-modal').exists()).toBe(false)
    vi.useRealTimers()

    await legacyRow?.findAll('button').find(button => button.text() === 'Disable')?.trigger('click')
    const legacyAction = wrapper.findAll('[role="dialog"]').find(dialog => dialog.text().includes('Confirm action'))
    expect(legacyAction?.text()).toContain('changes access to both VLESS and Hysteria 2')
    const actionBackdrop = wrapper.findAll('.modal-backdrop').find(backdrop => backdrop.find('.modal-small').exists())
    await actionBackdrop?.trigger('click.self')

    const revokedAccessRow = wrapper.findAll('.device-card').find(row => row.text().includes('revoked-access-phone'))
    expect(revokedAccessRow?.text()).toContain('revoked')

    const brokenRow = wrapper.findAll('.device-card').find(row => row.text().includes('broken-phone'))
    await brokenRow?.findAll('button').find(button => button.text() === 'Profile')?.trigger('click')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('profile store unavailable')

    const rawFailureRow = wrapper.findAll('.device-card').find(row => row.text().includes('raw-failure-phone'))
    await rawFailureRow?.findAll('button').find(button => button.text() === 'Profile')?.trigger('click')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('Request failed')
  })

  it('shows expiration-pending errors when expiry changes are rejected', async () => {
    const pendingClient = {
      ...sampleClient,
      enabled: false,
      expired: true,
      expirationPending: true,
      expiresAt: '2026-09-01T12:00:00Z',
    }
    const { wrapper } = await mountApp(request => {
      if (request.url.endsWith('/expiry')) return { status: 409, body: { error: 'worker is still applying expiry', code: 'expiration_pending' } }
      return defaultHandler({ authenticated: true, clients: [pendingClient] })(request)
    })

    expect(wrapper.get('.device-card .status-badge').text()).toBe('expiry pending')
    await wrapper.get('.expiry-button').trigger('click')
    await wrapper.get('[data-testid="expiry-preset"]').setValue('never')
    await wrapper.get('.modal form').trigger('submit')
    await flushPromises()

    expect(wrapper.get('[role="alert"]').text()).toContain('Expiry is being enforced')
    expect(wrapper.find('.modal-small').exists()).toBe(true)
    await wrapper.get('.modal-small .icon-button').trigger('click')
    expect(wrapper.find('.modal-small').exists()).toBe(false)
  })

  it('shows generic expiry errors when the server rejects a change for another reason', async () => {
    const { wrapper } = await mountApp(request => {
      if (request.url.endsWith('/expiry')) return { status: 500, body: { error: 'expiry update failed', code: 'internal_error' } }
      return defaultHandler({ authenticated: true, clients: [sampleClient] })(request)
    })
    await wrapper.get('.expiry-button').trigger('click')
    await wrapper.get('[role="dialog"] form').trigger('submit')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('expiry update failed')
    expect(wrapper.find('[role="dialog"]').exists()).toBe(true)
  })

  it('retains the unavailable state when AmneziaWG is enabled but unreachable', async () => {
    const { wrapper } = await mountApp(request => {
      if (request.url === '/api/transports/amneziawg') return { body: { enabled: true, available: false, running: false } }
      return defaultHandler({ authenticated: true })(request)
    })
    await openTab(wrapper, 'Settings')
    expect(wrapper.get('.settings-awg-card .status-badge').text()).toBe('Unavailable')
    expect(wrapper.get('.settings-awg-card').text()).toContain('The AmneziaWG container cannot be reached')

    await openTab(wrapper, 'Diagnostics')
    await wrapper.get('[data-testid="diagnostics-tab-awg"]').trigger('click')
    const section = wrapper.get('[data-testid="awg-diagnostics"]')
    expect(section.get('.status-badge').text()).toBe('Unavailable')
    expect(section.get('.status-badge').classes()).toContain('negative')
    expect(section.text()).toContain('The AmneziaWG container cannot be reached')
    await wrapper.get('[data-testid="diagnostics-tab-xray"]').trigger('click')
    await wrapper.get('[data-testid="diagnostics-tab-control-plane"]').trigger('click')
    expect(wrapper.get('[data-testid="control-plane-diagnostics"]').text()).toContain('No warnings or errors')
  })

  it('updates optional profile choices for valid, empty, and invalid certificate errors', async () => {
    const certificate = {
      subject: 'CN=vpn.example.com', issuer: 'CN=Example CA', dns_names: ['vpn.example.com'], ip_addresses: [],
      not_before: '2026-09-01T00:00:00Z', not_after: '2027-09-01T00:00:00Z', fingerprint: 'ABCD',
    }
    for (const certificateError of [undefined, '', 'certificate rejected'] as const) {
      const hysteria = {
        enabled: true, state: 'on', host: 'vpn.example.com', udp_port: 8443, tls_mode: 'custom', tls_server_name: 'vpn.example.com',
        udp_idle_timeout: 60, masquerade_type: 'off', insecure_uri: false, certificate,
        ...(certificateError === undefined ? {} : { certificate_error: certificateError }),
      }
      const { wrapper } = await mountApp(request => {
        if (request.url === '/api/transports/hysteria2') return { body: hysteria }
        return defaultHandler({ authenticated: true, settingsData: { ...settingsDto, shadowsocks_enabled: true, trojan_enabled: true } })(request)
      })
      await wrapper.findAll('button').find(button => button.text().includes('Create profile'))?.trigger('click')
      await flushPromises()
      const protocol = wrapper.get('[data-testid="profile-protocol"]')
      expect((protocol.find('option[value="hysteria2"]').element as HTMLOptionElement).disabled).toBe(certificateError === 'certificate rejected')
      expect((protocol.find('option[value="vmess"]').element as HTMLOptionElement).disabled).toBe(certificateError === 'certificate rejected')
      expect((protocol.find('option[value="shadowsocks"]').element as HTMLOptionElement).disabled).toBe(false)
      expect((protocol.find('option[value="trojan"]').element as HTMLOptionElement).disabled).toBe(certificateError === 'certificate rejected')
      await wrapper.get('.modal .icon-button').trigger('click')
      wrapper.unmount()
    }
  })

  it('shows stopped AmneziaWG diagnostics with placeholders when no peers are active', async () => {
    const { wrapper } = await mountApp(request => {
      if (request.url === '/api/transports/amneziawg') return { body: { enabled: true, available: true, running: false } }
      return defaultHandler({ authenticated: true })(request)
    })
    await openTab(wrapper, 'Settings')
    expect(wrapper.get('.settings-awg-card .status-badge').text()).toBe('Unavailable')
    expect(wrapper.get('.settings-awg-card dl').text()).toContain('—:—/UDP')
    await openTab(wrapper, 'Diagnostics')
    await wrapper.get('[data-testid="diagnostics-tab-awg"]').trigger('click')
    const section = wrapper.get('[data-testid="awg-diagnostics"]')
    expect(section.get('.status-badge').text()).toBe('Stopped')
    expect(section.get('.status-badge').classes()).toContain('negative')
    expect(section.text()).toContain('No AmneziaWG devices are currently connected')
  })

  it('shows complete AmneziaWG listener settings and active peers without optional metadata', async () => {
    const awgClient: Client = {
      id: 'awg:active', name: 'active-phone', protocol: 'amneziawg', protocols: ['amneziawg'],
      enabled: true, revoked: false, online: true, uploadBytes: 0, downloadBytes: 0,
    }
    const disabledAwgClient: Client = {
      ...awgClient, id: 'awg:disabled', name: 'disabled-phone', enabled: false, online: false,
    }
    const status = {
      enabled: true, available: true, running: true, public_key: 'server-key', public_host: 'vpn.example.com', public_port: 51820,
      listen_port: 51820, peer_count: 1, ipv4_network: '10.88.0.0/24', ipv6_network: 'fd88:88:88::/64', service_version: 'awg-v1',
    }
    const { wrapper } = await mountApp(request => {
      if (request.url === '/api/transports/amneziawg') return { body: status }
      return defaultHandler({ authenticated: true, clients: [awgClient, disabledAwgClient] })(request)
    })
    await openTab(wrapper, 'Settings')
    const settingsCard = wrapper.get('.settings-awg-card')
    expect(settingsCard.text()).toContain('vpn.example.com:51820/UDP')
    expect(settingsCard.text()).toContain('server-key')
    expect(settingsCard.text()).toContain('awg-v1')
    await openTab(wrapper, 'Diagnostics')
    await wrapper.get('[data-testid="diagnostics-tab-awg"]').trigger('click')
    const section = wrapper.get('[data-testid="awg-diagnostics"]')
    expect(section.text()).toContain('active-phone')
    expect(section.text()).toContain('— · Last seen: —')
  })

  it('shows Xray version and error diagnostics, and maps service states to settings tones', async () => {
    const status = {
      state: 'running', xray_version: '26.9.1', configured_xray_version: '26.9.0', xray_version_verified: false,
      last_error: 'runtime startup failed', stats_last_error: 'stats collection failed',
    }
    const { wrapper } = await mountApp(request => {
      if (request.url === '/api/status') return { body: status }
      return defaultHandler({ authenticated: true })(request)
    })
    await openTab(wrapper, 'Diagnostics')
    const xray = wrapper.get('[data-testid="xray-diagnostics"]')
    expect(xray.text()).toContain('This Xray version is experimental')
    expect(xray.text()).toContain('runtime startup failed')
    expect(xray.text()).toContain('stats collection failed')
    await openTab(wrapper, 'Settings')
    expect(wrapper.get('.settings-vless-card .status-badge').classes()).toContain('positive')

    for (const [state, label, tone] of [
      ['stopped', 'Stopped', 'negative'],
      ['new-state', 'Unknown', 'muted'],
    ] as const) {
      const next = await mountApp(request => {
        if (request.url === '/api/status') return { body: { state } }
        return defaultHandler({ authenticated: true })(request)
      })
      await openTab(next.wrapper, 'Settings')
      const badge = next.wrapper.get('.settings-vless-card .status-badge')
      expect(badge.text()).toContain(label)
      expect(badge.classes()).toContain(tone)
      next.wrapper.unmount()
    }
  })

  it('uses the fallback fingerprint and Trojan port, and renders each optional diagnostic error independently', async () => {
    const noFingerprintClient = { ...sampleClient, fingerprint: '' }
    const { wrapper } = await mountApp(request => {
      if (request.url === '/api/status') return { body: { state: 'running', stats_last_error: 'stats-only failure' } }
      return defaultHandler({
        authenticated: true,
        clients: [noFingerprintClient],
        settingsData: { ...settingsDto, client_fingerprint: '', trojan_enabled: true, trojan_public_port: 0 },
      })(request)
    })
    expect(wrapper.get('.device-meta').text()).toContain('chrome')
    await openTab(wrapper, 'Diagnostics')
    expect(wrapper.findAll('[data-testid="xray-diagnostics"] .diagnostic-alerts .error').map(item => item.text())).toEqual(['stats-only failure'])
    await openTab(wrapper, 'Settings')
    expect(wrapper.get('.settings-trojan-card').text()).toContain('—/TCP')
    wrapper.unmount()

    const lastErrorOnly = await mountApp(request => {
      if (request.url === '/api/status') return { body: { state: 'running', last_error: 'runtime-only failure' } }
      return defaultHandler({ authenticated: true })(request)
    })
    await openTab(lastErrorOnly.wrapper, 'Diagnostics')
    expect(lastErrorOnly.wrapper.findAll('[data-testid="xray-diagnostics"] .diagnostic-alerts .error').map(item => item.text())).toEqual(['runtime-only failure'])
    lastErrorOnly.wrapper.unmount()
  })

  it('ignores unsupported language-picker values and non-Escape keys', async () => {
    const { wrapper } = await mountApp(defaultHandler())
    const language = wrapper.get('.language')
    await language.setValue('ru')
    expect(window.localStorage.getItem('xray-easy-language')).toBe('ru')
    Object.defineProperty(language.element, 'value', { configurable: true, value: 'unsupported' })
    await language.trigger('change')
    expect(window.localStorage.getItem('xray-easy-language')).toBe('ru')
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter' }))
    expect(wrapper.findAll('[role="dialog"]')).toHaveLength(0)
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    await flushPromises()
    expect(wrapper.findAll('[role="dialog"]')).toHaveLength(0)
  })

})

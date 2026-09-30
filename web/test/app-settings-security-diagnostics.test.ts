import { describe, expect, it, vi } from 'vitest'
import type { VueWrapper } from '@vue/test-utils'
import type { Client } from '../src/domain/models'
import { defaultHandler, flushPromises, itemAt, mountApp, openTab, settings, hysteriaStatus, sampleClient, type RequestRecord } from './appHarness'

const preview = {
  change_id: 'change-123',
  expires_in: 300,
  expected_confirmation: 'REVOKE',
  requires_confirmation: true,
  diff: [{ field: 'public_host', from: 'old.example.com', to: 'new.example.com' }],
  consequences: ['All profiles will be revoked'],
  revoked_clients: 2,
    settings: { ...settings, public_host: 'new.example.com', log_level: 'warning' },
}

describe('connection settings', () => {
  it('removes repeated Settings and Security headings but keeps their useful status text', async () => {
    const { wrapper } = await mountApp(defaultHandler({ authenticated: true }))

    await openTab(wrapper, 'Settings')
    let panel = wrapper.get('.section-panel')
    expect(panel.find(':scope > .section-heading').exists()).toBe(false)
    expect(panel.get('.section-intro').text()).toContain('Configure each inbound')

    await openTab(wrapper, 'Security')
    panel = wrapper.get('.section-panel')
    expect(panel.find(':scope > .section-heading').exists()).toBe(false)
    expect(panel.get('.section-intro').text()).toContain('TOTP is not enabled')
  })

  it('shows the configured VMess port and its shared TLS certificate', async () => {
    const certificate = {
      subject: 'CN=vpn.example.com', issuer: 'CN=Example CA', dns_names: ['vpn.example.com'], ip_addresses: [],
      not_before: '2026-09-01T00:00:00Z', not_after: '2027-09-01T00:00:00Z', fingerprint: 'AABBCC',
    }
    const { wrapper } = await mountApp(request => {
      if (request.url === '/api/transports/hysteria2') return { body: { ...hysteriaStatus, certificate } }
      return defaultHandler({ authenticated: true, clients: [sampleClient] })(request)
    })
    await openTab(wrapper, 'Settings')
    const vmessCard = wrapper.get('.settings-vmess-card')
    expect(vmessCard.text()).toContain('9443/TCP')
    expect(vmessCard.text()).toContain('vpn.example.com')
    expect(vmessCard.text()).toContain('AABBCC')
    expect(vmessCard.find('a').attributes('href')).toBe('#hysteria-settings')
    expect(vmessCard.findAll('input')).toHaveLength(0)
  })

  it('reviews VLESS changes independently, confirms them, and reloads the current state', async () => {
    const requests: RequestRecord[] = []
    let applied = false
    const { wrapper } = await mountApp(request => {
      requests.push(request)
      if (request.method === 'PATCH' && request.url === '/api/settings') return { body: preview }
      if (request.method === 'POST' && request.url === '/api/settings/apply') { applied = true; return { status: 204 } }
      if (request.method === 'GET' && request.url === '/api/settings' && applied) return { body: preview.settings }
      return defaultHandler({ authenticated: true, clients: [sampleClient] })(request)
    })
    await openTab(wrapper, 'Settings')
    const vlessCard = wrapper.get('.settings-vless-card')
    const inputs = vlessCard.findAll('input')
    await itemAt(inputs, 0).setValue('new.example.com')
    await itemAt(inputs, 1).setValue('target.example.com:443')
    await itemAt(inputs, 2).setValue('target.example.com')
    await vlessCard.get('select').setValue('safari')
    await wrapper.get('.settings-logging-card select').setValue('debug')
    await vlessCard.get('.settings-danger-inline input[type="checkbox"]').setValue(true)
    await vlessCard.findAll('button').find(button => button.text() === 'Review VLESS changes')?.trigger('click')
    await flushPromises()

    expect(requests.find(request => request.url === '/api/settings' && request.method === 'PATCH')?.body).toEqual({
      public_host: 'new.example.com',
      reality_target: 'target.example.com:443',
      reality_sni: 'target.example.com',
      client_fingerprint: 'safari',
      log_level: 'warning',
      rotate_private_key: true,
    })
    const dialog = wrapper.get('[role="dialog"]')
    expect(dialog.text()).toContain('old.example.com → new.example.com')
    expect(dialog.text()).toContain('All profiles will be revoked')
    expect(dialog.text()).toContain('Profiles to revoke: 2')
    const apply = dialog.findAll('button').find(button => button.text() === 'Apply settings')!
    expect((apply.element as HTMLButtonElement).disabled).toBe(true)
    await dialog.get('input').setValue('REVOKE')
    expect((dialog.findAll('button').find(button => button.text() === 'Apply settings')!.element as HTMLButtonElement).disabled).toBe(false)
    await dialog.findAll('button').find(button => button.text() === 'Apply settings')!.trigger('click')
    await flushPromises()

    expect(requests.find(request => request.url === '/api/settings/apply')?.body).toEqual({ change_id: 'change-123', confirmation: 'REVOKE' })
    expect(wrapper.findAll('[role="dialog"]')).toHaveLength(0)
    expect((itemAt(vlessCard.findAll('input'), 0).element as HTMLInputElement).value).toBe('new.example.com')
    expect((wrapper.get('.settings-logging-card select').element as HTMLSelectElement).value).toBe('debug')
    expect(wrapper.get('[role="status"]').text()).toContain('Changes saved')
  })

  it('skips typed confirmation when the server says it is not required', async () => {
    const requests: RequestRecord[] = []
    const noConfirmation = {
      ...preview,
      expected_confirmation: '',
      requires_confirmation: false,
      revoked_clients: 0,
      diff: [{ field: 'log_level', from: 'warning', to: 'debug' }],
      consequences: ['Xray will restart and active connections will be briefly interrupted; existing profiles remain valid'],
      settings: { ...settings, log_level: 'debug' },
    }
    const { wrapper } = await mountApp(request => {
      requests.push(request)
      if (request.method === 'PATCH' && request.url === '/api/settings') return { body: noConfirmation }
      if (request.method === 'POST' && request.url === '/api/settings/apply') return { status: 204 }
      return defaultHandler({ authenticated: true })(request)
    })
    await openTab(wrapper, 'Settings')
    await wrapper.get('.settings-vless-card input').setValue('draft.example.com')
    await wrapper.get('.settings-logging-card select').setValue('debug')
    await wrapper.get('.settings-logging-card button').trigger('click')
    await flushPromises()
    expect(requests.find(request => request.url === '/api/settings' && request.method === 'PATCH')?.body).toEqual({
      public_host: 'vpn.example.com',
      reality_target: 'www.example.com:443',
      reality_sni: 'www.example.com',
      client_fingerprint: 'chrome',
      log_level: 'debug',
      rotate_private_key: false,
    })
    expect(wrapper.findAll('[role="dialog"] input')).toHaveLength(0)
    expect(wrapper.get('[role="dialog"]').text()).toContain('Log level: warning → debug')
    expect(wrapper.get('[role="dialog"]').text()).toContain('active connections will be briefly interrupted')
    expect(wrapper.get('[role="dialog"]').text()).not.toContain('Profiles to revoke')
    await wrapper.findAll('[role="dialog"] button').find(button => button.text() === 'Apply settings')!.trigger('click')
    await flushPromises()
    expect(requests.find(request => request.url === '/api/settings/apply')?.body).toEqual({ change_id: 'change-123', confirmation: '' })
    expect((wrapper.get('.settings-vless-card input').element as HTMLInputElement).value).toBe('draft.example.com')
  })

  it('keeps the confirmation review open if apply fails', async () => {
    const { wrapper } = await mountApp(request => {
      if (request.method === 'PATCH' && request.url === '/api/settings') return { body: preview }
      if (request.method === 'POST' && request.url === '/api/settings/apply') return { status: 502, body: { error: 'Xray apply failed' } }
      return defaultHandler({ authenticated: true })(request)
    })
    await openTab(wrapper, 'Settings')
    await wrapper.get('.settings-vless-card input').setValue('new.example.com')
    await wrapper.get('.settings-vless-card .section-actions button').trigger('click')
    await flushPromises()
    const dialog = wrapper.get('[role="dialog"]')
    await dialog.get('input').setValue('REVOKE')
    await dialog.findAll('button').find(button => button.text() === 'Apply settings')!.trigger('click')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('Xray apply failed')
    expect(wrapper.findAll('[role="dialog"]')).toHaveLength(1)
    expect((wrapper.get('[role="dialog"] input').element as HTMLInputElement).value).toBe('REVOKE')
  })

  it('cancels a settings review without applying it', async () => {
    const requests: RequestRecord[] = []
    const { wrapper } = await mountApp(request => {
      requests.push(request)
      if (request.method === 'PATCH' && request.url === '/api/settings') return { body: preview }
      return defaultHandler({ authenticated: true })(request)
    })
    await openTab(wrapper, 'Settings')
    await wrapper.get('.settings-vless-card input').setValue('new.example.com')
    await wrapper.get('.settings-vless-card .section-actions button').trigger('click')
    await flushPromises()
    await wrapper.get('[role="dialog"] .modal-actions .secondary').trigger('click')
    expect(wrapper.findAll('[role="dialog"]')).toHaveLength(0)
    expect(requests.some(request => request.url === '/api/settings/apply')).toBe(false)
  })

  it('shows preview errors without losing editable settings', async () => {
    const { wrapper } = await mountApp(request => {
      if (request.method === 'PATCH' && request.url === '/api/settings') return { status: 400, body: { error: 'Invalid REALITY target' } }
      return defaultHandler({ authenticated: true })(request)
    })
    await openTab(wrapper, 'Settings')
    await wrapper.get('.settings-vless-card input').setValue('new.example.com')
    await wrapper.get('.settings-vless-card .section-actions button').trigger('click')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('Invalid REALITY target')
    expect(wrapper.findAll('[role="dialog"]')).toHaveLength(0)
    expect((wrapper.get('.settings-vless-card input').element as HTMLInputElement).value).toBe('new.example.com')
  })
})

describe('backups and TOTP security', () => {
  it('changes the administrator password, closes the session, and asks for a new sign-in', async () => {
    const requests: RequestRecord[] = []
    const { wrapper, eventSources } = await mountApp(request => {
      requests.push(request)
      if (request.url === '/api/auth/password') return { status: 204 }
      return defaultHandler({ authenticated: true, clients: [sampleClient] })(request)
    })
    await openTab(wrapper, 'Security')
    const card = securityCard(wrapper, 'Administrator password')
    const inputs = card.findAll('input')
    await itemAt(inputs, 0).setValue('old-password')
    await itemAt(inputs, 1).setValue('a-new-password-long-enough')
    await itemAt(inputs, 2).setValue('does-not-match')
    expect(card.text()).toContain('The passwords do not match.')
    expect((card.get('button').element as HTMLButtonElement).disabled).toBe(true)

    await itemAt(inputs, 2).setValue('a-new-password-long-enough')
    expect((card.get('button').element as HTMLButtonElement).disabled).toBe(false)
    await card.get('form').trigger('submit')
    await flushPromises()

    expect(requests.find(request => request.url === '/api/auth/password')?.body).toEqual({
      current_password: 'old-password',
      new_password: 'a-new-password-long-enough',
    })
    expect(itemAt(eventSources, 0).closed).toBe(true)
    expect(wrapper.findAll('.security-card')).toHaveLength(0)
    expect(wrapper.text()).toContain('Password changed. Sign in with the new password.')
    expect(wrapper.text()).toContain('Administrator login')
  })

  it('keeps the current session and form when a password change fails', async () => {
    const { wrapper, eventSources } = await mountApp(request => {
      if (request.url === '/api/auth/password') return { status: 400, body: { error: 'Current password is incorrect' } }
      return defaultHandler({ authenticated: true })(request)
    })
    await openTab(wrapper, 'Security')
    const card = securityCard(wrapper, 'Administrator password')
    const inputs = card.findAll('input')
    await itemAt(inputs, 0).setValue('wrong-password')
    await itemAt(inputs, 1).setValue('a-new-password-long-enough')
    await itemAt(inputs, 2).setValue('a-new-password-long-enough')
    await card.get('form').trigger('submit')
    await flushPromises()

    expect(wrapper.get('[role="alert"]').text()).toContain('Current password is incorrect')
    expect(wrapper.findAll('.security-card')).toHaveLength(4)
    expect(itemAt(eventSources, 0).closed).toBe(false)
    expect((itemAt(card.findAll('input'), 0).element as HTMLInputElement).value).toBe('wrong-password')
  })

  it('creates a backup and displays the backup name', async () => {
    const requests: RequestRecord[] = []
    const { wrapper } = await mountApp(request => {
      requests.push(request)
      if (request.url === '/api/backups' && request.method === 'POST') return { body: { name: 'xray-easy-20260928.tar' } }
      return defaultHandler({ authenticated: true })(request)
    })
    await openTab(wrapper, 'Security')
    await securityCard(wrapper, 'Backups').get('button').trigger('click')
    await flushPromises()
    expect(requests.some(request => request.url === '/api/backups' && request.method === 'POST')).toBe(true)
    expect(wrapper.get('.backup-name').text()).toContain('xray-easy-20260928.tar')
    expect(wrapper.get('[role="status"]').text()).toContain('Backup is ready')
  })

  it('shows backup errors', async () => {
    const { wrapper } = await mountApp(request => {
      if (request.url === '/api/backups') return { status: 500, body: { error: 'Backup disk is full' } }
      return defaultHandler({ authenticated: true })(request)
    })
    await openTab(wrapper, 'Security')
    await securityCard(wrapper, 'Backups').get('button').trigger('click')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('Backup disk is full')
  })

  it('starts TOTP, displays its QR and recovery codes, and enables it after confirmation', async () => {
    const requests: RequestRecord[] = []
    let enabled = false
    const totpSetup = {
      setup_token: 'temporary-setup-token',
      secret: 'JBSWY3DPEHPK3PXP',
      otpauth_uri: 'otpauth://totp/Xray-easy:admin?secret=JBSWY3DPEHPK3PXP',
      qr_png: 'cXItcG5n',
      recovery_codes: ['AAAA-BBBB', 'CCCC-DDDD'],
      expires_in: 300,
    }
    const { wrapper } = await mountApp(request => {
      requests.push(request)
      if (request.url === '/api/auth/totp/setup') return { body: totpSetup }
      if (request.url === '/api/auth/totp/enable' && request.method === 'POST') { enabled = true; return { status: 204 } }
      if (request.url === '/api/auth/totp/status') return { body: { enabled, recovery_codes_remaining: enabled ? 2 : 0 } }
      return defaultHandler({ authenticated: true })(request)
    })
    await openTab(wrapper, 'Security')
    await findButton(securityCard(wrapper, 'Two-factor authentication'), 'Enable TOTP').trigger('click')
    await flushPromises()
    expect(wrapper.get('.totp-qr').attributes('src')).toBe('data:image/png;base64,cXItcG5n')
    expect(wrapper.get('.recovery-codes').text()).toContain('AAAA-BBBB')
    expect((wrapper.get('.totp-setup-fields input').element as HTMLInputElement).value).toBe(totpSetup.secret)
    expect((wrapper.get('.totp-setup-fields textarea').element as HTMLTextAreaElement).value).toBe(totpSetup.otpauth_uri)
    await wrapper.get('.security-card input[autocomplete="one-time-code"]').setValue('123456')
    await findButton(wrapper, 'Confirm TOTP').trigger('click')
    await flushPromises()

    expect(requests.find(request => request.url === '/api/auth/totp/enable')?.body).toEqual({ setup_token: 'temporary-setup-token', code: '123456' })
    expect(wrapper.text()).toContain('TOTP is enabled')
    expect(window.localStorage.getItem('xray-easy-totp-secret')).toBeNull()
    expect(window.localStorage.getItem('xray-easy-language')).toBe('en')
  })

  it('keeps the TOTP setup available after an invalid confirmation code', async () => {
    const { wrapper } = await mountApp(request => {
      if (request.url === '/api/auth/totp/setup') return { body: { setup_token: 'setup', secret: 'secret', otpauth_uri: 'otpauth://test', qr_png: '', recovery_codes: [], expires_in: 300 } }
      if (request.url === '/api/auth/totp/enable') return { status: 400, body: { error: 'Invalid TOTP code' } }
      return defaultHandler({ authenticated: true })(request)
    })
    await openTab(wrapper, 'Security')
    await findButton(securityCard(wrapper, 'Two-factor authentication'), 'Enable TOTP').trigger('click')
    await flushPromises()
    await securityCard(wrapper, 'Two-factor authentication').get('input[autocomplete="one-time-code"]').setValue('000000')
    await findButton(wrapper, 'Confirm TOTP').trigger('click')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('Invalid TOTP code')
    expect(wrapper.findAll('.recovery-codes')).toHaveLength(1)
  })

  it('disables TOTP only after sending password and code, then closes the session', async () => {
    const requests: RequestRecord[] = []
    const { wrapper, eventSources } = await mountApp(request => {
      requests.push(request)
      if (request.url === '/api/auth/totp/disable') return { status: 204 }
      return defaultHandler({ authenticated: true, totpData: { enabled: true, recovery_codes_remaining: 3 } })(request)
    })
    await openTab(wrapper, 'Security')
    await securityCard(wrapper, 'Two-factor authentication').get('input[autocomplete="current-password"]').setValue('correct-password')
    await securityCard(wrapper, 'Two-factor authentication').get('input[autocomplete="one-time-code"]').setValue('654321')
    await findButton(wrapper, 'Disable TOTP').trigger('click')
    await flushPromises()
    expect(requests.find(request => request.url === '/api/auth/totp/disable')?.body).toEqual({ password: 'correct-password', code: '654321' })
    expect(itemAt(eventSources, 0).closed).toBe(true)
    expect(wrapper.text()).toContain('Administrator login')
  })

  it('keeps TOTP enabled and shows the error when disabling it fails', async () => {
    const { wrapper, eventSources } = await mountApp(request => {
      if (request.url === '/api/auth/totp/disable') return { status: 401, body: { error: 'Invalid TOTP code' } }
      return defaultHandler({ authenticated: true, totpData: { enabled: true, recovery_codes_remaining: 3 } })(request)
    })
    await openTab(wrapper, 'Security')
    await securityCard(wrapper, 'Two-factor authentication').get('input[autocomplete="current-password"]').setValue('correct-password')
    await securityCard(wrapper, 'Two-factor authentication').get('input[autocomplete="one-time-code"]').setValue('000000')
    await findButton(wrapper, 'Disable TOTP').trigger('click')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('Invalid TOTP code')
    expect(wrapper.text()).toContain('TOTP is enabled')
    expect(itemAt(eventSources, 0).closed).toBe(false)
  })
})

describe('diagnostics', () => {
  it('shows AmneziaWG service health and active device connection details without a duplicate heading', async () => {
    const awgClient: Client = {
      ...sampleClient,
      id: 'awg:iphone',
      name: 'iphone',
      protocol: 'amneziawg',
      protocols: ['amneziawg'],
      online: true,
      sourceIPs: ['198.51.100.24'],
    }
    const status = {
      enabled: true, available: true, running: true, public_host: 'vpn.example.com', public_port: 1234,
      listen_port: 51820, peer_count: 2, ipv4_network: '10.88.0.0/24', ipv6_network: 'fd88:88:88::/64',
      service_version: 'prototype-v1',
    }
    const { wrapper } = await mountApp(request => {
      if (request.url === '/api/transports/amneziawg') return { body: status }
      return defaultHandler({ authenticated: true, clients: [awgClient] })(request)
    })
    await openTab(wrapper, 'Diagnostics')
    expect(wrapper.find('.section-panel > .section-heading').exists()).toBe(false)
    expect(wrapper.find('.diagnostics-toolbar .diagnostics-tabs').exists()).toBe(true)
    expect(wrapper.get('[data-testid="diagnostics-tab-xray"]').attributes('aria-selected')).toBe('true')
    expect(wrapper.get('[data-testid="awg-diagnostics"]').isVisible()).toBe(false)
    await wrapper.get('[data-testid="diagnostics-tab-awg"]').trigger('click')

    const section = wrapper.get('[data-testid="awg-diagnostics"]')
    expect(section.text()).toContain('Running')
    expect(section.text()).toContain('vpn.example.com:1234/UDP')
    expect(section.text()).toContain('2')
    expect(section.text()).toContain('1')
    expect(section.text()).toContain('10.88.0.0/24')
    expect(section.text()).toContain('prototype-v1')
    expect(section.text()).toContain('iphone')
    expect(section.text()).toContain('198.51.100.24')
  })

  it('reports an unreachable AmneziaWG status endpoint as unavailable', async () => {
    const { wrapper } = await mountApp(request => {
      if (request.url === '/api/transports/amneziawg') return { status: 503, body: { error: 'service unavailable' } }
      return defaultHandler({ authenticated: true })(request)
    })
    await openTab(wrapper, 'Diagnostics')
    await wrapper.get('[data-testid="diagnostics-tab-awg"]').trigger('click')

    const section = wrapper.get('[data-testid="awg-diagnostics"]')
    expect(section.get('.status-badge').text()).toBe('Unavailable')
    expect(section.text()).toContain('The AmneziaWG container cannot be reached')
    expect(section.text()).not.toContain('AmneziaWG is not enabled')
  })

  it('keeps Xray and control plane events in separate diagnostic sections', async () => {
    const { wrapper } = await mountApp(request => {
      if (request.url === '/api/logs?component=xray&limit=100') return { body: { entries: [
        { at: '2026-09-28T03:00:00Z', component: 'xray', level: 'warning', message: 'late warning' },
        { at: '2026-09-28T01:00:00Z', component: 'xray', level: 'warn', message: 'early warning' },
      ] } }
      if (request.url === '/api/logs?component=app&limit=100') return { body: { entries: [
        { at: '2026-09-28T02:00:00Z', component: 'app', level: 'error', message: 'middle error' },
      ] } }
      return defaultHandler({ authenticated: true })(request)
    })
    await openTab(wrapper, 'Diagnostics')
    const xraySection = wrapper.get('[data-testid="xray-diagnostics"]')
    expect(wrapper.get('[data-testid="diagnostics-tab-xray"]').text()).toBe('Xray')
    expect(xraySection.get('.diagnostic-summary').text()).toContain('2 warnings')
    expect(xraySection.get('.diagnostic-summary').text()).toContain('0 errors')
    expect(xraySection.findAll('.diagnostic-event').map(event => event.text())).toEqual([
      expect.stringContaining('early warning'),
      expect.stringContaining('late warning'),
    ])
    await wrapper.get('[data-testid="diagnostics-tab-control-plane"]').trigger('click')
    const controlPlaneSection = wrapper.get('[data-testid="control-plane-diagnostics"]')
    expect(controlPlaneSection.findAll('.diagnostic-event').map(event => event.text())).toEqual([
      expect.stringContaining('middle error'),
    ])
  })

  it('keeps the available log source if the other source fails', async () => {
    const { wrapper } = await mountApp(request => {
      if (request.url === '/api/logs?component=xray&limit=100') return { body: { entries: [{
        at: '2026-09-28T01:00:00Z', component: 'xray', level: 'error', message: 'xray failure',
      }] } }
      if (request.url === '/api/logs?component=app&limit=100') return { status: 502, body: { error: 'app log unavailable' } }
      return defaultHandler({ authenticated: true })(request)
    })
    await openTab(wrapper, 'Diagnostics')
    expect(wrapper.text()).toContain('xray failure')
    expect(wrapper.text()).not.toContain('app log unavailable')
    expect(wrapper.get('.diagnostic-summary').text()).toContain('1 errors')
  })

  it('shows an unavailable status when the Xray status endpoint fails', async () => {
    const { wrapper } = await mountApp(request => {
      if (request.url === '/api/status') return { status: 503, body: { error: 'not ready' } }
      return defaultHandler({ authenticated: true })(request)
    })
    await openTab(wrapper, 'Diagnostics')
    expect(wrapper.get('.diagnostic-status-card').text()).toContain('Unavailable')
    expect(wrapper.get('.diagnostic-summary').text()).toContain('0')
  })

  it('retains only the newest 100 diagnostic entries', async () => {
    const entries = Array.from({ length: 101 }, (_, index) => ({
      at: new Date(Date.UTC(2026, 8, 28, 0, 0, index)).toISOString(),
      component: 'xray', level: 'info', message: `event-${index}`,
    }))
    const { wrapper } = await mountApp(request => {
      if (request.url === '/api/logs?component=xray&limit=100') return { body: { entries } }
      if (request.url === '/api/logs?component=app&limit=100') return { body: { entries: [] } }
      return defaultHandler({ authenticated: true })(request)
    })
    await openTab(wrapper, 'Diagnostics')
    expect(wrapper.findAll('.diagnostic-event')).toHaveLength(100)
    expect(wrapper.text()).not.toContain('event-0')
    expect(wrapper.text()).toContain('event-100')
  })

  it('refreshes Xray status and both log sources on demand', async () => {
    const requests: RequestRecord[] = []
    const { wrapper } = await mountApp(request => {
      requests.push(request)
      return defaultHandler({ authenticated: true })(request)
    })
    await openTab(wrapper, 'Diagnostics')
    const before = requests.length
    vi.useFakeTimers()
    const refreshButton = wrapper.get('[aria-label="Refresh diagnostics"]')
    await refreshButton.trigger('click')
    await flushPromises()
    expect(refreshButton.get('svg').classes()).toContain('spinning')
    const refreshed = requests.slice(before).map(request => request.url)
    expect(refreshed).toEqual(expect.arrayContaining([
      '/api/status',
      '/api/logs?component=xray&limit=100',
      '/api/logs?component=app&limit=100',
      '/api/transports/amneziawg',
    ]))
    await vi.advanceTimersByTimeAsync(2500)
    expect(refreshButton.get('svg').classes()).not.toContain('spinning')
  })
})

function findButton(wrapper: { findAll(selector: string): Array<{ text(): string; trigger(event: string): Promise<unknown> }> }, label: string) {
  const button = wrapper.findAll('button').find(item => item.text().trim().includes(label))
  if (!button) throw new Error(`Button not found: ${label}`)
  return button
}

function securityCard(wrapper: VueWrapper, heading: string) {
  const card = wrapper.findAll('.security-card').find(item => item.get('h3').text() === heading)
  if (!card) throw new Error(`Security card not found: ${heading}`)
  return card
}

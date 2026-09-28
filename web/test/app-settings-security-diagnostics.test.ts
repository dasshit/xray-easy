import { describe, expect, it } from 'vitest'
import { defaultHandler, flushPromises, itemAt, mountApp, openTab, settings, sampleClient, type RequestRecord } from './appHarness'

const preview = {
  change_id: 'change-123',
  expires_in: 300,
  expected_confirmation: 'REVOKE',
  requires_confirmation: true,
  diff: [{ field: 'public_host', from: 'old.example.com', to: 'new.example.com' }],
  consequences: ['All profiles will be revoked'],
  revoked_clients: 2,
  settings: { ...settings, public_host: 'new.example.com' },
}

describe('connection settings', () => {
  it('reviews, confirms, applies settings, and reloads the current state', async () => {
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
    const inputs = wrapper.findAll('.settings-card input')
    await itemAt(inputs, 0).setValue('new.example.com')
    await itemAt(inputs, 1).setValue('target.example.com:443')
    await itemAt(inputs, 2).setValue('target.example.com')
    await wrapper.get('.settings-card select').setValue('safari')
    await wrapper.get('.settings-card-danger input[type="checkbox"]').setValue(true)
    await wrapper.get('.section-actions button').trigger('click')
    await flushPromises()

    expect(requests.find(request => request.url === '/api/settings' && request.method === 'PATCH')?.body).toEqual({
      public_host: 'new.example.com',
      reality_target: 'target.example.com:443',
      reality_sni: 'target.example.com',
      client_fingerprint: 'safari',
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
    expect((itemAt(wrapper.findAll('.settings-card input'), 0).element as HTMLInputElement).value).toBe('new.example.com')
    expect(wrapper.get('[role="status"]').text()).toContain('Changes saved')
  })

  it('skips typed confirmation when the server says it is not required', async () => {
    const requests: RequestRecord[] = []
    const noConfirmation = { ...preview, requires_confirmation: false, revoked_clients: 0 }
    const { wrapper } = await mountApp(request => {
      requests.push(request)
      if (request.method === 'PATCH' && request.url === '/api/settings') return { body: noConfirmation }
      if (request.method === 'POST' && request.url === '/api/settings/apply') return { status: 204 }
      return defaultHandler({ authenticated: true })(request)
    })
    await openTab(wrapper, 'Settings')
    await wrapper.get('.section-actions button').trigger('click')
    await flushPromises()
    expect(wrapper.findAll('[role="dialog"] input')).toHaveLength(0)
    await wrapper.findAll('[role="dialog"] button').find(button => button.text() === 'Apply settings')!.trigger('click')
    await flushPromises()
    expect(requests.find(request => request.url === '/api/settings/apply')?.body).toEqual({ change_id: 'change-123', confirmation: '' })
  })

  it('keeps the confirmation review open if apply fails', async () => {
    const { wrapper } = await mountApp(request => {
      if (request.method === 'PATCH' && request.url === '/api/settings') return { body: preview }
      if (request.method === 'POST' && request.url === '/api/settings/apply') return { status: 502, body: { error: 'Xray apply failed' } }
      return defaultHandler({ authenticated: true })(request)
    })
    await openTab(wrapper, 'Settings')
    await wrapper.get('.section-actions button').trigger('click')
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
    await wrapper.get('.section-actions button').trigger('click')
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
    await wrapper.get('.section-actions button').trigger('click')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('Invalid REALITY target')
    expect(wrapper.findAll('[role="dialog"]')).toHaveLength(0)
    expect(wrapper.findAll('.settings-card input')).toHaveLength(4)
  })
})

describe('backups and TOTP security', () => {
  it('creates a backup and displays the backup name', async () => {
    const requests: RequestRecord[] = []
    const { wrapper } = await mountApp(request => {
      requests.push(request)
      if (request.url === '/api/backups' && request.method === 'POST') return { body: { name: 'xray-easy-20260928.tar' } }
      return defaultHandler({ authenticated: true })(request)
    })
    await openTab(wrapper, 'Security')
    await wrapper.get('.security-card button').trigger('click')
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
    await wrapper.get('.security-card button').trigger('click')
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
    await wrapper.get('.security-card .security-action-button').trigger('click')
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
    await wrapper.get('.security-card .security-action-button').trigger('click')
    await flushPromises()
    await wrapper.get('.security-card input[autocomplete="one-time-code"]').setValue('000000')
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
    await wrapper.get('.security-card input[autocomplete="current-password"]').setValue('correct-password')
    await wrapper.get('.security-card input[autocomplete="one-time-code"]').setValue('654321')
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
    await wrapper.get('.security-card input[autocomplete="current-password"]').setValue('correct-password')
    await wrapper.get('.security-card input[autocomplete="one-time-code"]').setValue('000000')
    await findButton(wrapper, 'Disable TOTP').trigger('click')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('Invalid TOTP code')
    expect(wrapper.text()).toContain('TOTP is enabled')
    expect(itemAt(eventSources, 0).closed).toBe(false)
  })
})

describe('diagnostics', () => {
  it('combines available logs, sorts them, and counts warn and warning levels', async () => {
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
    expect(wrapper.get('.diagnostic-summary').text()).toContain('2 warnings')
    expect(wrapper.get('.diagnostic-summary').text()).toContain('1 errors')
    expect(wrapper.findAll('.diagnostic-event').map(event => event.text())).toEqual([
      expect.stringContaining('early warning'),
      expect.stringContaining('middle error'),
      expect.stringContaining('late warning'),
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
    await findButton(wrapper, 'Refresh diagnostics').trigger('click')
    await flushPromises()
    const refreshed = requests.slice(before).map(request => request.url)
    expect(refreshed).toEqual(expect.arrayContaining([
      '/api/status',
      '/api/logs?component=xray&limit=100',
      '/api/logs?component=app&limit=100',
    ]))
  })
})

function findButton(wrapper: { findAll(selector: string): Array<{ text(): string; trigger(event: string): Promise<unknown> }> }, label: string) {
  const button = wrapper.findAll('button').find(item => item.text().trim().includes(label))
  if (!button) throw new Error(`Button not found: ${label}`)
  return button
}

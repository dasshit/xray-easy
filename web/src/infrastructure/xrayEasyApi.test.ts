import { describe, expect, it, vi } from 'vitest'
import { createXrayEasyApi } from './xrayEasyApi'

function sequence(...values: unknown[]) {
  return { responses: [...values] }
}

function requester(responses: Record<string, unknown>) {
  const calls: Array<{ url: string; options?: RequestInit }> = []
  const send = vi.fn((url: string, options?: RequestInit): Promise<unknown> => {
    calls.push({ url, ...(options === undefined ? {} : { options }) })
    const result = responses[url]
    if (result !== null && typeof result === 'object' && 'responses' in result && Array.isArray(result.responses)) {
      return Promise.resolve(result.responses.shift())
    }
    return Promise.resolve(result)
  })
  return { send, calls }
}

describe('Xray-easy API adapter', () => {
  it('omits absent optional wire fields from mapped domain models', async () => {
    const { send } = requester({
      '/api/setup/status': { initialized: true },
      '/api/me': { username: 'admin' },
      '/api/clients': [{ id: 'client-1', name: 'phone', protocol: 'vless', protocols: ['vless'], vless: { enabled: true, revoked: false }, enabled: true, revoked: false, online: false, upload_bytes: 0, download_bytes: 0 }],
      '/api/auth/totp/setup': {
        setup_token: 'setup-token', secret: 'secret', otpauth_uri: 'otpauth://totp/test', recovery_codes: [], expires_in: 300,
      },
      '/api/status': { state: 'running', restart_count: 0 },
    })
    const api = createXrayEasyApi(send)

    await expect(api.setup.status()).resolves.toEqual({ initialized: true })
    await expect(api.auth.current()).resolves.toEqual({ username: 'admin' })
    await expect(api.clients.list()).resolves.toEqual([{
      id: 'client-1', name: 'phone', protocol: 'vless', protocols: ['vless'], vless: { enabled: true, revoked: false }, enabled: true, revoked: false, online: false, uploadBytes: 0, downloadBytes: 0,
    }])
    await expect(api.auth.beginTOTPSetup()).resolves.toEqual({
      setupToken: 'setup-token', secret: 'secret', otpauthUri: 'otpauth://totp/test', recoveryCodes: [], expiresIn: 300,
    })
    await expect(api.diagnostics.status()).resolves.toEqual({ state: 'running', restartCount: 0 })
  })

  it('maps setup and administrator wire values and sends setup fields in API format', async () => {
    const { send, calls } = requester({
      '/api/setup/status': { initialized: false, public_port: 18443, suggested_public_host: '89.169.13.234' },
      '/api/me': { username: 'admin', totp_enabled: true, recovery_codes_remaining: 4 },
    })
    const api = createXrayEasyApi(send)

    await expect(api.setup.status()).resolves.toEqual({ initialized: false, publicPort: 18443, suggestedPublicHost: '89.169.13.234' })
    await api.setup.initialize({
      username: 'admin', password: 'secret', publicHost: 'vpn.example.test', publicPort: 18443,
      realityTarget: 'www.example.test:443', realitySni: 'www.example.test',
    })
    await expect(api.auth.current()).resolves.toEqual({ username: 'admin', totpEnabled: true, recoveryCodesRemaining: 4 })
    expect(calls[1]).toEqual({
      url: '/api/setup/initialize',
      options: {
        method: 'POST',
        body: JSON.stringify({ username: 'admin', password: 'secret', public_host: 'vpn.example.test', public_port: 18443, reality_target: 'www.example.test:443', reality_sni: 'www.example.test' }),
      },
    })
  })

  it('rejects a successful response that does not match its DTO schema', async () => {
    const { send } = requester({ '/api/setup/status': { initialized: 'yes' } })
    const api = createXrayEasyApi(send)

    await expect(api.setup.status()).rejects.toMatchObject({
      name: 'APIError',
      message: 'The server returned an invalid response',
      code: 'invalid_response',
    })
  })

  it('maps client and profile responses, encodes path IDs, and sends lifecycle actions', async () => {
    const clientDto = {
      id: 'device/1', name: 'phone', protocol: 'vless', protocols: ['vless'], vless: { enabled: true, revoked: false }, enabled: true, revoked: false, fingerprint: 'safari', online: false,
      last_seen: '2026-09-28T12:00:00Z', upload_bytes: 22, download_bytes: 33,
    }
    const { send, calls } = requester({
      '/api/clients': sequence([clientDto], clientDto),
      '/api/clients/device%2F1/profile?format=uri': { client_id: 'device/1', protocol: 'vless', uri: 'vless://id', json: { id: 'id' } },
      '/api/clients/device%2F1/disable': { ...clientDto, enabled: false },
    })
    const api = createXrayEasyApi(send)
    const expected = {
      id: 'device/1', name: 'phone', protocol: 'vless', protocols: ['vless'], vless: { enabled: true, revoked: false }, enabled: true, revoked: false, fingerprint: 'safari', online: false,
      lastSeen: '2026-09-28T12:00:00Z', uploadBytes: 22, downloadBytes: 33,
    }

    await expect(api.clients.list()).resolves.toEqual([expected])
    await expect(api.clients.profile('device/1')).resolves.toEqual({ clientId: 'device/1', protocol: 'vless', uri: 'vless://id', json: { id: 'id' } })
    await expect(api.clients.setAction('device/1', 'disable')).resolves.toMatchObject({ enabled: false, uploadBytes: 22 })
    await expect(api.clients.create({ name: 'tablet', protocol: 'vless' })).resolves.toEqual(expected)
    expect(calls[2]).toMatchObject({ url: '/api/clients/device%2F1/disable', options: { method: 'POST' } })
    expect(calls[3]).toMatchObject({ url: '/api/clients', options: { method: 'POST', body: JSON.stringify({ name: 'tablet', protocol: 'vless' }) } })
    expect(api.clients.profileQrUrl('device/1')).toBe('/api/clients/device%2F1/profile?format=qr')
    expect(api.clients.profileJsonUrl('device/1')).toBe('/api/clients/device%2F1/profile?format=json')
  })

  it('creates Hysteria profiles with optional auth and validates Hysteria-only delivery', async () => {
    const hysteriaDto = {
      id: 'hyst-1', name: 'tablet', protocol: 'hysteria2', protocols: ['hysteria2'],
      hysteria2: { enabled: true, revoked: false }, enabled: true, revoked: false, online: false, upload_bytes: 0, download_bytes: 0,
    }
    const { send, calls } = requester({
      '/api/clients': hysteriaDto,
      '/api/clients/hyst-1/profile?format=uri': { client_id: 'hyst-1', protocol: 'hysteria2', hysteria_uri: 'hysteria2://password@vpn.test:443' },
    })
    const api = createXrayEasyApi(send)

    await expect(api.clients.create({ name: 'tablet', protocol: 'hysteria2', auth: 'custom-password' })).resolves.toMatchObject({
      protocol: 'hysteria2', protocols: ['hysteria2'], hysteria2: { enabled: true, revoked: false },
    })
    expect(calls[0]?.options?.body).toBe(JSON.stringify({ name: 'tablet', protocol: 'hysteria2', auth: 'custom-password' }))
    await expect(api.clients.profile('hyst-1')).resolves.toEqual({
      clientId: 'hyst-1', protocol: 'hysteria2', hysteriaUri: 'hysteria2://password@vpn.test:443',
    })
  })

  it('creates a VMess profile and validates its link, JSON export, and QR URL', async () => {
    const vmessDto = {
      id: 'vmess-1', name: 'macbook', protocol: 'vmess', protocols: ['vmess'],
      vmess: { enabled: true, revoked: false }, enabled: true, revoked: false, online: false, upload_bytes: 0, download_bytes: 0,
    }
    const { send, calls } = requester({
      '/api/clients': vmessDto,
      '/api/clients/vmess-1/profile?format=uri': { client_id: 'vmess-1', protocol: 'vmess', vmess_uri: 'vmess://encoded', json: { outbound: true } },
    })
    const api = createXrayEasyApi(send)

    await expect(api.clients.create({ name: 'macbook', protocol: 'vmess' })).resolves.toMatchObject({
      protocol: 'vmess', protocols: ['vmess'], vmess: { enabled: true, revoked: false },
    })
    expect(calls[0]?.options?.body).toBe(JSON.stringify({ name: 'macbook', protocol: 'vmess' }))
    await expect(api.clients.profile('vmess-1')).resolves.toEqual({
      clientId: 'vmess-1', protocol: 'vmess', vmessUri: 'vmess://encoded', json: { outbound: true },
    })
    expect(api.clients.profileVMessQrUrl('vmess-1')).toBe('/api/clients/vmess-1/profile?format=vmess-qr')
  })

  it('rejects a profile response that omits its protocol discriminator', async () => {
    const { send } = requester({
      '/api/clients/device-1/profile?format=uri': { client_id: 'device-1', uri: 'vless://id', json: {} },
    })
    const api = createXrayEasyApi(send)
    await expect(api.clients.profile('device-1')).rejects.toMatchObject({
      name: 'APIError', code: 'invalid_response', message: 'The server returned an invalid response',
    })
  })

  it('maps settings preview, serializes apply, and preserves TOTP wire contracts', async () => {
    const settingsDto = {
      public_host: 'vpn.example.test', public_port: 443, reality_target: 'target.example.test:443', reality_sni: 'target.example.test',
      client_fingerprint: 'chrome', log_level: 'warning', protocol: 'vless', network: 'tcp', security: 'reality', flow: 'xtls-rprx-vision',
    }
    const previewDto = {
      change_id: 'change-1', expires_in: 300, expected_confirmation: 'REVOKE', requires_confirmation: true,
      diff: [{ field: 'public_host', from: 'old.test', to: 'vpn.example.test' }], consequences: ['profiles revoked'],
      revoked_clients: 3, settings: settingsDto,
    }
    const totpSetupDto = {
      setup_token: 'setup-token', secret: 'secret', otpauth_uri: 'otpauth://totp/test', qr_png: 'cXItcG5n',
      recovery_codes: ['one-time'], expires_in: 300,
    }
    const { send, calls } = requester({
      '/api/settings': sequence(settingsDto, previewDto),
      '/api/auth/totp/status': { enabled: true, recovery_codes_remaining: 2 },
      '/api/auth/totp/setup': totpSetupDto,
      '/api/settings/apply': {},
      '/api/auth/totp/enable': {},
      '/api/auth/totp/disable': {},
    })
    const api = createXrayEasyApi(send)
    const settings = {
      publicHost: 'vpn.example.test', publicPort: 443, realityTarget: 'target.example.test:443', realitySni: 'target.example.test',
      clientFingerprint: 'chrome', logLevel: 'warning', protocol: 'vless', network: 'tcp', security: 'reality', flow: 'xtls-rprx-vision',
    }

    await expect(api.settings.get()).resolves.toEqual(settings)
    const preview = await api.settings.preview({
      publicHost: 'vpn.example.test', realityTarget: 'target.example.test:443', realitySni: 'target.example.test',
      clientFingerprint: 'safari', logLevel: 'error', rotatePrivateKey: true,
    })
    expect(preview).toMatchObject({
      changeId: 'change-1', expectedConfirmation: 'REVOKE', revokedClients: 3,
      settings,
    })
    expect('confirmation' in preview).toBe(false)
    expect(calls[1]?.options?.body).toBe(JSON.stringify({
      public_host: 'vpn.example.test', reality_target: 'target.example.test:443', reality_sni: 'target.example.test',
      client_fingerprint: 'safari', log_level: 'error', rotate_private_key: true,
    }))
    await api.settings.apply('change-1', 'REVOKE')
    await expect(api.auth.totpStatus()).resolves.toEqual({ enabled: true, recoveryCodesRemaining: 2 })
    await expect(api.auth.beginTOTPSetup()).resolves.toEqual({
      setupToken: 'setup-token', secret: 'secret', otpauthUri: 'otpauth://totp/test', qrPng: 'cXItcG5n',
      recoveryCodes: ['one-time'], expiresIn: 300,
    })
    await api.auth.enableTOTP('setup-token', '123456')
    await api.auth.disableTOTP('password', '654321')
    expect(calls.some(call => call.url === '/api/settings/apply' && call.options?.body === JSON.stringify({ change_id: 'change-1', confirmation: 'REVOKE' }))).toBe(true)
    expect(calls.some(call => call.url === '/api/auth/totp/enable' && call.options?.body === JSON.stringify({ setup_token: 'setup-token', code: '123456' }))).toBe(true)
    expect(calls.some(call => call.url === '/api/auth/totp/disable' && call.options?.body === JSON.stringify({ password: 'password', code: '654321' }))).toBe(true)
  })

  it('maps Hysteria status, stages certificates, previews settings, and applies them', async () => {
    const certificate = {
      subject: 'CN=vpn.example.test', issuer: 'CN=Example CA', dns_names: ['vpn.example.test'], ip_addresses: [],
      not_before: '2026-09-01T00:00:00Z', not_after: '2027-09-01T00:00:00Z', fingerprint: 'ABCD',
    }
    const settings = {
      enabled: false, state: 'ready', host: 'vpn.example.test', udp_port: 443, tls_mode: 'custom', tls_server_name: 'vpn.example.test',
      certificate_id: '1234567890abcdef1234567890abcdef', certificate, udp_idle_timeout: 60,
      masquerade_type: 'off', insecure_uri: false,
    }
    const { send, calls } = requester({
      '/api/transports/hysteria2': settings,
      '/api/transports/hysteria2/certificate': { certificate_id: settings.certificate_id, certificate },
      '/api/transports/hysteria2/certificate/mkcert': { certificate_id: settings.certificate_id, certificate },
      '/api/transports/hysteria2/preview': sequence(
        { changed: false, settings },
        {
          changed: true, change_id: 'hysteria-change', expires_in: 600, expected_confirmation: 'APPLY', requires_confirmation: true,
          diff: [{ field: 'enabled', from: 'false', to: 'true' }], consequences: ['replace Hysteria inbound'], settings: { ...settings, enabled: true, state: 'applying' },
        },
      ),
      '/api/transports/hysteria2/apply': {},
    })
    const api = createXrayEasyApi(send)
    await expect(api.hysteria.status()).resolves.toMatchObject({
      state: 'ready', udpPort: 443, tlsMode: 'custom', certificate: { fingerprint: 'ABCD' }, insecureUri: false,
    })
    const fullchain = new File(['certificate'], 'fullchain.pem')
    const privateKey = new File(['key'], 'privkey.pem')
    await expect(api.hysteria.uploadCertificate(fullchain, privateKey, 'vpn.example.test')).resolves.toMatchObject({
      certificateId: settings.certificate_id, certificate: { fingerprint: 'ABCD' },
    })
    await api.hysteria.generateCertificate('89.169.13.234')
    const input = {
      enabled: true, host: 'vpn.example.test', tlsMode: 'custom' as const, tlsCertIp: '', tlsServerName: 'vpn.example.test',
      certificateId: settings.certificate_id, udpIdleTimeout: 60, masqueradeType: 'off' as const, masqueradeString: '',
    }
    await expect(api.hysteria.preview(input)).resolves.toMatchObject({ changed: false })
    await expect(api.hysteria.preview(input)).resolves.toMatchObject({ changed: true, changeId: 'hysteria-change', expectedConfirmation: 'APPLY' })
    await api.hysteria.apply('hysteria-change', 'APPLY')

    const uploadCall = calls.find(call => call.url === '/api/transports/hysteria2/certificate')
    expect(uploadCall?.options?.body).toBeInstanceOf(FormData)
    const upload = uploadCall?.options?.body
    if (!(upload instanceof FormData)) throw new Error('certificate upload was not encoded as multipart form data')
    expect(upload.get('fullchain')).toBe(fullchain)
    expect(upload.get('private_key')).toBe(privateKey)
    expect(upload.get('server_name')).toBe('vpn.example.test')
    expect(uploadCall?.options?.headers).toEqual({})
    expect(calls.some(call => call.url === '/api/transports/hysteria2/certificate/mkcert' && call.options?.body === JSON.stringify({ ipv4: '89.169.13.234' }))).toBe(true)
    expect(calls.some(call => call.url === '/api/transports/hysteria2/preview' && call.options?.body === JSON.stringify({
      enabled: true, host: 'vpn.example.test', tls_mode: 'custom', tls_cert_ip: '', tls_server_name: 'vpn.example.test',
      certificate_id: settings.certificate_id, udp_idle_timeout: 60, masquerade_type: 'off', masquerade_string: '',
    }))).toBe(true)
    expect(calls.some(call => call.url === '/api/transports/hysteria2/apply' && call.options?.body === JSON.stringify({ change_id: 'hysteria-change', confirmation: 'APPLY' }))).toBe(true)
  })

  it('maps diagnostics and exposes backup and authentication requests', async () => {
    const { send, calls } = requester({
      '/api/status': {
        state: 'running', restart_count: 2, last_error: 'xray failing', last_exit: 'exited (1)',
        stats_last_error: 'stats offline', supervisor_error: 'supervisor warning',
      },
      '/api/logs?component=xray&limit=50': { entries: [{ at: '2026-09-28T12:00:00Z', component: 'xray', level: 'warn', message: 'warning' }] },
      '/api/backups': { name: 'backup.tar' },
      '/api/auth/login': { username: 'admin', totp_enabled: false },
      '/api/auth/login/totp': { username: 'admin', totp_enabled: true },
      '/api/auth/login/recovery': { username: 'admin', recovery_codes_remaining: 1 },
      '/api/auth/logout': {},
      '/api/auth/logout-all': {},
    })
    const api = createXrayEasyApi(send)

    await expect(api.diagnostics.status()).resolves.toEqual({
      state: 'running', restartCount: 2, lastError: 'xray failing', lastExit: 'exited (1)',
      statsLastError: 'stats offline', supervisorError: 'supervisor warning',
    })
    await expect(api.diagnostics.logs('xray', 50)).resolves.toEqual([{ at: '2026-09-28T12:00:00Z', component: 'xray', level: 'warn', message: 'warning' }])
    await expect(api.backups.create()).resolves.toEqual({ name: 'backup.tar' })
    await expect(api.auth.login('admin', 'password')).resolves.toMatchObject({ username: 'admin', totpEnabled: false })
    await expect(api.auth.loginWithTOTP('admin', 'password', '123456')).resolves.toMatchObject({ totpEnabled: true })
    await expect(api.auth.loginWithRecoveryCode('admin', 'password', 'ABCD')).resolves.toMatchObject({ recoveryCodesRemaining: 1 })
    await api.auth.logout()
    await api.auth.logoutAll()
    expect(calls.find(call => call.url === '/api/logs?component=xray&limit=50')).toBeDefined()
    expect(calls.filter(call => call.options?.method === 'POST')).toHaveLength(6)
  })
})

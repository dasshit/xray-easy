import { describe, expect, it } from 'vitest'
import { defaultHandler, flushPromises, itemAt, mountApp, openTab, submitLogin } from './appHarness'

describe('setup and authentication screens', () => {
  it('shows an initial setup status error', async () => {
    const { wrapper } = await mountApp(() => ({ status: 502, body: { error: 'Control plane unavailable' } }))
    expect(wrapper.get('[role="alert"]').text()).toContain('Control plane unavailable')
    expect(wrapper.get('form.auth-card').text()).toContain('Create administrator')
  })

  it('shows initial setup and submits the public port and entered values', async () => {
    const requests = [] as Array<{ url: string; method: string; body: unknown }>
    const { wrapper } = await mountApp(request => {
      requests.push(request)
      if (request.url === '/api/setup/status') return { body: { initialized: false, public_port: 18443, suggested_public_host: '89.169.13.234' } }
      if (request.url === '/api/setup/initialize') return { status: 201 }
      return { status: 404, body: { error: 'Unexpected request' } }
    })

    expect(wrapper.text()).toContain('Initial setup')
    const form = wrapper.get('form.auth-card')
    expect((form.get('input[type="number"]').element as HTMLInputElement).value).toBe('18443')
    expect((form.get('input[placeholder="vpn.example.com"]').element as HTMLInputElement).value).toBe('89.169.13.234')
    await form.get('input[autocomplete="username"]').setValue('admin')
    await form.get('input[autocomplete="new-password"]').setValue('long-password')
    await form.get('input[placeholder="www.cloudflare.com:443"]').setValue('www.cloudflare.com:443')
    await form.get('input[placeholder="www.cloudflare.com"]').setValue('www.cloudflare.com')
    await form.trigger('submit')
    await flushPromises()

    expect(requests.find(request => request.url === '/api/setup/initialize')?.body).toEqual({
      username: 'admin',
      password: 'long-password',
      public_host: '89.169.13.234',
      public_port: 18443,
      reality_target: 'www.cloudflare.com:443',
      reality_sni: 'www.cloudflare.com',
    })
    expect(wrapper.text()).toContain('Administrator login')
  })

  it('keeps the setup form visible and displays an initialization error', async () => {
    const { wrapper } = await mountApp(request => {
      if (request.url === '/api/setup/status') return { body: { initialized: false } }
      return { status: 400, body: { error: 'Invalid public host' } }
    })
    const form = wrapper.get('form.auth-card')
    await form.trigger('submit')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('Invalid public host')
    expect(wrapper.get('form.auth-card').text()).toContain('Create administrator')
  })

  it('shows login when the server is initialized but there is no valid session', async () => {
    const { wrapper } = await mountApp(defaultHandler())
    expect(wrapper.text()).toContain('Administrator login')
    expect(wrapper.text()).not.toContain('Profiles')
  })

  it('restores an existing session and loads the dashboard', async () => {
    const { wrapper, requests, eventSources } = await mountApp(defaultHandler({ authenticated: true }))
    expect(wrapper.text()).toContain('Profiles')
    expect(wrapper.find('.dashboard-header').exists()).toBe(false)
    expect(wrapper.find('.dashboard > .tabs').exists()).toBe(true)
    expect(requests.map(request => request.url)).toEqual(expect.arrayContaining([
      '/api/clients',
      '/api/auth/totp/status',
      '/api/settings',
      '/api/status',
      '/api/logs?component=xray&limit=100',
      '/api/logs?component=app&limit=100',
    ]))
    expect(eventSources).toHaveLength(1)
    expect(itemAt(eventSources, 0).url).toBe('/api/events')
  })

  it('shows login failure and releases the busy state', async () => {
    const { wrapper } = await mountApp(request => {
      if (request.url === '/api/auth/login') return { status: 401, body: { error: 'Invalid credentials' } }
      return defaultHandler()(request)
    })
    await submitLogin(wrapper)
    expect(wrapper.get('[role="alert"]').text()).toContain('Invalid credentials')
    expect((wrapper.get('button[type="submit"]').element as HTMLButtonElement).disabled).toBe(false)
  })

  it('signs in with a password and opens the dashboard', async () => {
    const requests: Array<{ url: string; method: string; body: unknown }> = []
    const { wrapper } = await mountApp(request => {
      requests.push(request)
      if (request.url === '/api/auth/login') return { body: { username: 'admin' } }
      return defaultHandler()(request)
    })
    await submitLogin(wrapper)
    expect(requests.find(request => request.url === '/api/auth/login')?.body).toEqual({
      username: 'admin', password: 'correct-password',
    })
    expect(wrapper.text()).toContain('Profiles')
  })

  it('switches to the TOTP step for totp_required and submits the second factor', async () => {
    const requests: Array<{ url: string; method: string; body: unknown }> = []
    const { wrapper } = await mountApp(request => {
      requests.push(request)
      if (request.url === '/api/auth/login') return { status: 401, body: { error: 'TOTP required', code: 'totp_required' } }
      if (request.url === '/api/auth/login/totp') return { body: { username: 'admin', totp_enabled: true } }
      return defaultHandler()(request)
    })
    await submitLogin(wrapper)
    expect(wrapper.text()).toContain('TOTP code')
    await wrapper.get('input[autocomplete="one-time-code"]').setValue('123456')
    await wrapper.get('form.auth-card').trigger('submit')
    await flushPromises()

    expect(requests.find(request => request.url === '/api/auth/login/totp')?.body).toEqual({
      username: 'admin', password: 'correct-password', totp_code: '123456',
    })
    expect(wrapper.text()).toContain('Profiles')
  })

  it('shows an invalid TOTP error and leaves the second-factor form available', async () => {
    const { wrapper } = await mountApp(request => {
      if (request.url === '/api/auth/login') return { status: 401, body: { error: 'TOTP required', code: 'totp_required' } }
      if (request.url === '/api/auth/login/totp') return { status: 401, body: { error: 'Invalid TOTP code' } }
      return defaultHandler()(request)
    })
    await submitLogin(wrapper)
    await wrapper.get('input[autocomplete="one-time-code"]').setValue('000000')
    await wrapper.get('form.auth-card').trigger('submit')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('Invalid TOTP code')
    expect(wrapper.text()).toContain('TOTP code')
  })

  it('allows recovery-code login after the TOTP challenge', async () => {
    const requests: Array<{ url: string; method: string; body: unknown }> = []
    const { wrapper } = await mountApp(request => {
      requests.push(request)
      if (request.url === '/api/auth/login') return { status: 401, body: { error: 'TOTP required', code: 'totp_required' } }
      if (request.url === '/api/auth/login/recovery') return { body: { username: 'admin', totp_enabled: true } }
      return defaultHandler()(request)
    })
    await submitLogin(wrapper)
    await wrapper.get('button.secondary').trigger('click')
    expect(wrapper.text()).toContain('Recovery code')
    await wrapper.get('input[autocomplete="one-time-code"]').setValue('ABCD-EFGH')
    await wrapper.get('form.auth-card').trigger('submit')
    await flushPromises()
    expect(requests.find(request => request.url === '/api/auth/login/recovery')?.body).toEqual({
      username: 'admin', password: 'correct-password', recovery_code: 'ABCD-EFGH',
    })
    expect(wrapper.text()).toContain('Profiles')
  })

  it('releases the busy state when post-login dashboard loading fails', async () => {
    let loginCount = 0
    const { wrapper } = await mountApp(request => {
      if (request.url === '/api/auth/login') { loginCount += 1; return { body: { username: 'admin' } } }
      if (request.url === '/api/clients' && loginCount > 0) return { status: 503, body: { error: 'Client service unavailable' } }
      return defaultHandler()(request)
    })
    await submitLogin(wrapper)
    expect(wrapper.get('[role="alert"]').text()).toContain('Client service unavailable')
    expect((wrapper.findAll('button.secondary').find(button => button.text() === 'Sign out')!.element as HTMLButtonElement).disabled).toBe(false)
  })
})

describe('session exit', () => {
  it.each([
    ['/api/auth/logout', 'Sign out'],
    ['/api/auth/logout-all', 'Sign out all sessions'],
  ])('closes SSE and returns to login after %s', async (path, label) => {
    const { wrapper, eventSources, requests } = await mountApp(request => {
      if (request.url === path) return { status: 204 }
      return defaultHandler({ authenticated: true })(request)
    })
    if (label === 'Sign out all sessions') await openTab(wrapper, 'Security')
    await wrapper.findAll('button.secondary').find(button => button.text() === label)!.trigger('click')
    await flushPromises()
    expect(requests.some(request => request.url === path && request.method === 'POST')).toBe(true)
    expect(itemAt(eventSources, 0).closed).toBe(true)
    expect(wrapper.text()).toContain('Administrator login')
  })

  it('keeps the session active and reports failure if logout-all is rejected', async () => {
    const { wrapper, eventSources } = await mountApp(request => {
      if (request.url === '/api/auth/logout-all') return { status: 500, body: { error: 'Could not revoke sessions' } }
      return defaultHandler({ authenticated: true })(request)
    })
    await openTab(wrapper, 'Security')
    const button = wrapper.findAll('button.secondary').find(item => item.text() === 'Sign out all sessions')!
    await button.trigger('click')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('Could not revoke sessions')
    expect(wrapper.text()).toContain('Profiles')
    expect(itemAt(eventSources, 0).closed).toBe(false)
  })
})

import { describe, expect, it, vi } from 'vitest'
import { defaultHandler, FakeEventSource, flushPromises, mountApp, sampleClient, type RequestRecord } from './appHarness'

describe('theme and language preferences in the interface', () => {
  it('toggles theme and persists it for the next visit', async () => {
    const { wrapper } = await mountApp(defaultHandler())
    await wrapper.get('.theme-toggle').trigger('click')
    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(window.localStorage.getItem('xray-easy-theme')).toBe('dark')
    expect(wrapper.get('.theme-toggle').attributes('aria-label')).toBe('Light theme')

    await wrapper.get('.theme-toggle').trigger('click')
    expect(document.documentElement.dataset.theme).toBe('light')
    expect(window.localStorage.getItem('xray-easy-theme')).toBe('light')
  })

  it('switches between English and Russian and persists the choice', async () => {
    const { wrapper } = await mountApp(defaultHandler())
    const language = wrapper.get('.language')
    expect(language.text()).toBe('Русский')
    await language.trigger('click')
    expect(wrapper.text()).toContain('Войти')
    expect(wrapper.get('.language').text()).toBe('English')
    expect(window.localStorage.getItem('xray-easy-language')).toBe('ru')
    await wrapper.get('.language').trigger('click')
    expect(wrapper.text()).toContain('Sign in')
    expect(window.localStorage.getItem('xray-easy-language')).toBe('en')
  })
})

describe('SSE updates and recovery', () => {
  it('refreshes profiles when a stats event arrives', async () => {
    let clients = [] as typeof sampleClient[]
    const { wrapper, eventSources, requests } = await mountApp(request => {
      if (request.url === '/api/clients') return { body: clients }
      return defaultHandler({ authenticated: true })(request)
    })
    clients = [sampleClient]
    const requestsBefore = requests.filter(request => request.url === '/api/clients').length
    eventSources[0].emit('stats')
    await flushPromises()
    expect(requests.filter(request => request.url === '/api/clients')).toHaveLength(requestsBefore + 1)
    expect(wrapper.get('.device-card').text()).toContain('phone')
  })

  it('refreshes status and diagnostics when a status event arrives', async () => {
    const requests: RequestRecord[] = []
    const { eventSources } = await mountApp(request => {
      requests.push(request)
      return defaultHandler({ authenticated: true })(request)
    })
    const statusCalls = requests.filter(request => request.url === '/api/status').length
    const logCalls = requests.filter(request => request.url.startsWith('/api/logs?')).length
    eventSources[0].emit('status')
    await flushPromises()
    expect(requests.filter(request => request.url === '/api/status')).toHaveLength(statusCalls + 1)
    expect(requests.filter(request => request.url.startsWith('/api/logs?'))).toHaveLength(logCalls + 2)
  })

  it('closes an errored stream and reconnects once after three seconds', async () => {
    const { eventSources } = await mountApp(defaultHandler({ authenticated: true }))
    vi.useFakeTimers()
    eventSources[0].fail()
    expect(eventSources[0].closed).toBe(true)
    await vi.advanceTimersByTimeAsync(2999)
    expect(FakeEventSource.instances).toHaveLength(1)
    await vi.advanceTimersByTimeAsync(1)
    expect(FakeEventSource.instances).toHaveLength(2)
    await vi.advanceTimersByTimeAsync(6000)
    expect(FakeEventSource.instances).toHaveLength(2)
  })

  it('cancels a pending reconnect when the administrator signs out', async () => {
    const { wrapper, eventSources } = await mountApp(request => {
      if (request.url === '/api/auth/logout') return { status: 204 }
      return defaultHandler({ authenticated: true })(request)
    })
    vi.useFakeTimers()
    eventSources[0].fail()
    await wrapper.findAll('button.secondary').find(button => button.text() === 'Sign out')!.trigger('click')
    await flushPromises()
    await vi.advanceTimersByTimeAsync(5000)
    expect(eventSources).toHaveLength(1)
    expect(wrapper.text()).toContain('Administrator login')
  })

  it('does not reconnect after the component unmounts', async () => {
    const { wrapper, eventSources } = await mountApp(defaultHandler({ authenticated: true }))
    vi.useFakeTimers()
    eventSources[0].fail()
    wrapper.unmount()
    await vi.advanceTimersByTimeAsync(5000)
    expect(eventSources).toHaveLength(1)
  })

  it('closes an active stream when the component unmounts', async () => {
    const { wrapper, eventSources } = await mountApp(defaultHandler({ authenticated: true }))
    wrapper.unmount()
    expect(eventSources[0].closed).toBe(true)
  })

  it('keeps the administrator signed in and reports a failed logout', async () => {
    const { wrapper, eventSources } = await mountApp(request => {
      if (request.url === '/api/auth/logout') return { status: 500, body: { error: 'Logout failed' } }
      return defaultHandler({ authenticated: true })(request)
    })
    await wrapper.findAll('button.secondary').find(button => button.text() === 'Sign out')!.trigger('click')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('Logout failed')
    expect(wrapper.text()).toContain('Profiles')
    expect(eventSources[0].closed).toBe(false)
  })

  it('renders starting, stopped, and unknown service states', async () => {
    for (const [state, label, tone] of [
      ['starting', 'Starting', 'neutral'],
      ['stopped', 'Stopped', 'negative'],
      ['restarting', 'Unknown', 'neutral'],
    ] as const) {
      const { wrapper } = await mountApp(defaultHandler({ authenticated: true, statusData: { state, restart_count: 0 } }))
      expect(wrapper.get('.node-pill').text()).toContain(label)
      expect(wrapper.get('.node-pill').classes()).toContain(`node-pill-${tone}`)
      wrapper.unmount()
    }
  })

  it('closes the create dialog with Escape', async () => {
    const { wrapper } = await mountApp(defaultHandler({ authenticated: true }))
    await wrapper.findAll('button').find(button => button.text().includes('Create profile'))!.trigger('click')
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    await flushPromises()
    expect(wrapper.findAll('[role="dialog"]')).toHaveLength(0)
  })
})

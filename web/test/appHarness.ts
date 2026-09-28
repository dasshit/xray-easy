import { afterEach, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import type { Client, DiagnosticEntry, NodeStatus, Settings, TOTPStatus } from '../src/domain/models'
import App from '../src/App.vue'

export type RequestRecord = { url: string; method: string; body: unknown }
export type RequestHandler = (request: RequestRecord) => { status?: number; body?: unknown }

export const admin = { username: 'admin', totp_enabled: false, recovery_codes_remaining: 0 }
export const sampleClient: Client = {
  id: 'client-12345678',
  name: 'phone',
  enabled: true,
  revoked: false,
  fingerprint: 'safari',
  online: false,
  last_seen: '2026-09-27T12:30:00Z',
  upload_bytes: 2048,
  download_bytes: 1024,
}
export const settings: Settings = {
  public_host: 'vpn.example.com',
  public_port: 443,
  reality_target: 'www.example.com:443',
  reality_sni: 'www.example.com',
  client_fingerprint: 'chrome',
  protocol: 'vless',
  network: 'tcp',
  security: 'reality',
  flow: 'xtls-rprx-vision',
}
export const totpStatus: TOTPStatus = { enabled: false, recovery_codes_remaining: 0 }
export const nodeStatus: NodeStatus = { state: 'running', restart_count: 2 }
export const xrayEntries: DiagnosticEntry[] = []
export const appEntries: DiagnosticEntry[] = []

export function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: vi.fn().mockResolvedValue(body),
  } as unknown as Response
}

export class FakeEventSource {
  static instances: FakeEventSource[] = []
  readonly listeners = new Map<string, Array<(event: Event) => void>>()
  closed = false
  onerror: ((this: EventSource, event: Event) => unknown) | null = null

  constructor(readonly url: string) {
    FakeEventSource.instances.push(this)
  }

  addEventListener(type: string, listener: EventListenerOrEventListenerObject | null): void {
    if (!listener) return
    const callback = typeof listener === 'function' ? listener : (event: Event) => listener.handleEvent(event)
    this.listeners.set(type, [...(this.listeners.get(type) || []), callback])
  }

  close(): void {
    this.closed = true
  }

  emit(type: string): void {
    for (const listener of this.listeners.get(type) || []) listener(new Event(type))
  }

  fail(): void {
    this.onerror?.call(this as unknown as EventSource, new Event('error'))
  }
}

const mounted: VueWrapper[] = []
afterEach(() => {
  for (const wrapper of mounted.splice(0)) wrapper.unmount()
  document.body.innerHTML = ''
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
  vi.useRealTimers()
})

export async function mountApp(handler: RequestHandler) {
  window.localStorage.clear()
  window.localStorage.setItem('xray-easy-language', 'en')
  FakeEventSource.instances = []
  vi.stubGlobal('matchMedia', vi.fn(() => ({ matches: false })))
  vi.stubGlobal('navigator', {
    language: 'en-US',
    clipboard: { writeText: vi.fn().mockResolvedValue(undefined) },
  })

  const requests: RequestRecord[] = []
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString()
    const method = (init?.method || 'GET').toUpperCase()
    let body: unknown
    if (typeof init?.body === 'string') body = JSON.parse(init.body)
    const request = { url, method, body }
    requests.push(request)
    const response = handler(request)
    return jsonResponse(response.body ?? {}, response.status ?? 200)
  })
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('EventSource', FakeEventSource)

  const wrapper = mount(App, { attachTo: document.body })
  mounted.push(wrapper)
  await flushPromises()
  return { wrapper, requests, fetchMock, eventSources: FakeEventSource.instances }
}

export function defaultHandler({ initialized = true, authenticated = false, clients = [] as Client[], settingsData = settings } = {}): RequestHandler {
  return ({ method, url }) => {
    if (method === 'GET' && url === '/api/setup/status') return { body: { initialized, public_port: 8443 } }
    if (method === 'GET' && url === '/api/me') return authenticated ? { body: admin } : { status: 401, body: { error: 'Unauthorized' } }
    if (method === 'GET' && url === '/api/clients') return { body: clients }
    if (method === 'GET' && url === '/api/auth/totp/status') return { body: totpStatus }
    if (method === 'GET' && url === '/api/settings') return { body: settingsData }
    if (method === 'GET' && url === '/api/status') return { body: nodeStatus }
    if (method === 'GET' && url === '/api/logs?component=xray&limit=100') return { body: { entries: xrayEntries } }
    if (method === 'GET' && url === '/api/logs?component=app&limit=100') return { body: { entries: appEntries } }
    return { status: 404, body: { error: `No mock route for ${method} ${url}` } }
  }
}

export async function submitLogin(wrapper: VueWrapper) {
  const form = wrapper.get('form.auth-card')
  await form.get('input[autocomplete="username"]').setValue('admin')
  await form.get('input[autocomplete="current-password"]').setValue('correct-password')
  await form.trigger('submit')
  await flushPromises()
}

export { flushPromises }

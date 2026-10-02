import { afterEach, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import type { DiagnosticEntry } from '../src/application/models'
import type { Client } from '../src/domain/models'
import type { ClientDto, NodeStatusDto, SettingsDto, TOTPStatusDto } from '../src/infrastructure/api-contracts'
import { xrayEasyApi } from '../src/infrastructure/xrayEasyApi'
import { xrayEasyGatewayKey } from '../src/presentation/api'
import App from '../src/App.vue'

export type RequestRecord = { url: string; method: string; body: unknown }
export type RequestHandler = (request: RequestRecord) => { status?: number; body?: unknown }

export const admin = { username: 'admin', totp_enabled: false, recovery_codes_remaining: 0 }
export const sampleClient: Client = {
  id: 'client-12345678',
  name: 'phone',
  protocol: 'vless',
  protocols: ['vless'],
  vless: { enabled: true, revoked: false },
  enabled: true,
  revoked: false,
  fingerprint: 'safari',
  online: false,
  lastSeen: '2026-09-27T12:30:00Z',
  uploadBytes: 2048,
  downloadBytes: 1024,
}
export const settings: SettingsDto = {
  public_host: 'vpn.example.com',
  public_port: 443,
  vmess_public_port: 9443,
  shadowsocks_enabled: false,
  shadowsocks_public_port: 8388,
  shadowsocks_method: 'chacha20-poly1305',
  shadowsocks_network: 'tcp,udp',
  trojan_enabled: false,
  trojan_public_port: 10443,
  reality_target: 'www.example.com:443',
  reality_sni: 'www.example.com',
  client_fingerprint: 'chrome',
  log_level: 'warning',
  protocol: 'vless',
  network: 'tcp',
  security: 'reality',
  flow: 'xtls-rprx-vision',
}
export const totpStatus: TOTPStatusDto = { enabled: false, recovery_codes_remaining: 0 }
export const hysteriaStatus = {
  enabled: false,
  state: 'ready',
  host: 'vpn.example.com',
  udp_port: 8443,
  tls_mode: 'custom',
  tls_server_name: 'vpn.example.com',
  udp_idle_timeout: 60,
  masquerade_type: 'off',
  insecure_uri: false,
}
export const nodeStatus: NodeStatusDto = { state: 'running' }
export const xrayEntries: DiagnosticEntry[] = []
export const appEntries: DiagnosticEntry[] = []

export function clientDto(client: Client): ClientDto {
  return {
    id: client.id,
    name: client.name,
    protocol: client.protocol,
    protocols: client.protocols,
    ...(client.vless === undefined ? {} : { vless: client.vless }),
    ...(client.hysteria2 === undefined ? {} : { hysteria2: client.hysteria2 }),
    enabled: client.enabled,
    revoked: client.revoked,
    online: client.online,
    upload_bytes: client.uploadBytes,
    download_bytes: client.downloadBytes,
    upload_bytes_per_second: client.uploadBytesPerSecond ?? 0,
    download_bytes_per_second: client.downloadBytesPerSecond ?? 0,
    ...(client.sourceIPs === undefined ? {} : { source_ips: client.sourceIPs }),
    ...(client.fingerprint === undefined ? {} : { fingerprint: client.fingerprint }),
    ...(client.lastSeen === undefined ? {} : { last_seen: client.lastSeen }),
  }
}

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
  const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof Request ? input.url : input.toString()
    const methodName = init?.method
    const method = (methodName === undefined || methodName === '' ? 'GET' : methodName).toUpperCase()
    let body: unknown
    if (typeof init?.body === 'string') body = JSON.parse(init.body)
    const request = { url, method, body }
    requests.push(request)
    const response = handler(request)
    return Promise.resolve(jsonResponse(response.body ?? {}, response.status ?? 200))
  })
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('EventSource', FakeEventSource)

  const wrapper = mount(App, {
    attachTo: document.body,
    global: { provide: { [xrayEasyGatewayKey as symbol]: xrayEasyApi } },
  })
  mounted.push(wrapper)
  await flushPromises()
  return { wrapper, requests, fetchMock, eventSources: FakeEventSource.instances }
}

export function itemAt<T>(items: readonly T[], index: number): T {
  const item = items[index]
  if (item === undefined) throw new Error(`Expected an item at index ${index}`)
  return item
}

export function defaultHandler({ initialized = true, authenticated = false, clients = [] as Client[], settingsData = settings, totpData = totpStatus, statusData = nodeStatus } = {}): RequestHandler {
  return ({ method, url }) => {
    if (method === 'GET' && url === '/api/setup/status') return { body: { initialized, public_port: 8443 } }
    if (method === 'GET' && url === '/api/me') return authenticated ? { body: admin } : { status: 401, body: { error: 'Unauthorized' } }
    if (method === 'GET' && url === '/api/clients') return { body: clients.map(clientDto) }
    if (method === 'POST' && url === '/api/clients') return { status: 201, body: clientDto({ ...sampleClient, name: 'new-device' }) }
    const profilePath = url.match(/^\/api\/clients\/([^/]+)\/profile\?format=uri$/)
    if (method === 'GET' && profilePath) return { body: { client_id: profilePath[1], protocol: 'vless', uri: `vless://${profilePath[1]}@vpn.example.com:443?security=reality#phone`, json: { id: profilePath[1] } } }
    if (method === 'GET' && url === '/api/auth/totp/status') return { body: totpData }
    if (method === 'GET' && url === '/api/settings') return { body: settingsData }
    if (method === 'GET' && url === '/api/transports/hysteria2') return { body: hysteriaStatus }
    if (method === 'GET' && url === '/api/transports/amneziawg') return { body: { enabled: false, available: false, running: false } }
    if (method === 'GET' && url === '/api/status') return { body: statusData }
    if (method === 'GET' && url === '/api/logs?component=xray&limit=100') return { body: { entries: xrayEntries } }
    if (method === 'GET' && url === '/api/logs?component=app&limit=100') return { body: { entries: appEntries } }
    return { status: 404, body: { error: `No mock route for ${method} ${url}` } }
  }
}

export async function openTab(wrapper: VueWrapper, label: string): Promise<void> {
  const tab = wrapper.findAll('[role="tab"]').find(item => item.text() === label)
  if (!tab) throw new Error(`Tab not found: ${label}`)
  await tab.trigger('click')
  await flushPromises()
}

export async function submitLogin(wrapper: VueWrapper) {
  const form = wrapper.get('form.auth-card')
  await form.get('input[autocomplete="username"]').setValue('admin')
  await form.get('input[autocomplete="current-password"]').setValue('correct-password')
  await form.trigger('submit')
  await flushPromises()
}

export { flushPromises }

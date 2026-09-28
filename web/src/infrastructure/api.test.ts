import { afterEach, describe, expect, it, vi } from 'vitest'
import { APIError, request } from './api'

function response({ ok, status, body }: { ok: boolean; status: number; body?: unknown }) {
  return {
    ok,
    status,
    json: body === undefined ? vi.fn().mockRejectedValue(new SyntaxError('invalid JSON')) : vi.fn().mockResolvedValue(body),
  } as unknown as Response
}

afterEach(() => vi.unstubAllGlobals())

describe('request', () => {
  it('sends JSON headers and returns the decoded successful response', async () => {
    const fetchMock = vi.fn().mockResolvedValue(response({ ok: true, status: 200, body: { ready: true } }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(request<{ ready: boolean }>('/api/status')).resolves.toEqual({ ready: true })
    expect(fetchMock).toHaveBeenCalledWith('/api/status', { headers: { 'Content-Type': 'application/json' } })
  })

  it('forwards method, body, and request options', async () => {
    const fetchMock = vi.fn().mockResolvedValue(response({ ok: true, status: 200, body: { created: true } }))
    vi.stubGlobal('fetch', fetchMock)
    const options: RequestInit = { method: 'POST', body: JSON.stringify({ name: 'phone' }) }

    await request('/api/clients', options)
    expect(fetchMock).toHaveBeenCalledWith('/api/clients', {
      headers: { 'Content-Type': 'application/json' },
      ...options,
    })
  })

  it('returns an empty object for a successful response without JSON', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ ok: true, status: 204 })))
    await expect(request('/api/auth/logout', { method: 'POST' })).resolves.toEqual({})
  })

  it('exposes the server message and error code on APIError', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({
      ok: false,
      status: 401,
      body: { error: 'Invalid code', code: 'totp_required' },
    })))

    await expect(request('/api/auth/login')).rejects.toMatchObject({
      name: 'APIError',
      message: 'Invalid code',
      code: 'totp_required',
    })
  })

  it('falls back to the HTTP status when an error response has no message', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ ok: false, status: 503, body: {} })))
    await expect(request('/api/status')).rejects.toMatchObject({ message: 'HTTP 503' })
  })

  it.each([
    ['a non-object payload', null],
    ['error fields with unexpected types', { error: { message: 'Invalid request' }, code: 42 }],
  ])('uses the HTTP status for %s', async (_description, body) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ ok: false, status: 400, body })))
    await expect(request('/api/status')).rejects.toMatchObject({ message: 'HTTP 400' })
  })

  it('treats a non-JSON error response as an HTTP error', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ ok: false, status: 502 })))
    await expect(request('/api/status')).rejects.toBeInstanceOf(APIError)
    await expect(request('/api/status')).rejects.toMatchObject({ message: 'HTTP 502' })
  })

  it('preserves a network error', async () => {
    const networkError = new TypeError('Failed to fetch')
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(networkError))
    await expect(request('/api/status')).rejects.toBe(networkError)
  })
})

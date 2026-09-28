import { APIError } from '../application/errors'

export { APIError } from '../application/errors'

export async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(url, { headers: { 'Content-Type': 'application/json' }, ...options })
  const payload: unknown = await response.json().catch(() => ({}))
  if (!response.ok) {
    const errorPayload = isRecord(payload) ? payload : {}
    const message = typeof errorPayload.error === 'string' ? errorPayload.error : `HTTP ${response.status}`
    const code = typeof errorPayload.code === 'string' ? errorPayload.code : undefined
    throw new APIError(message, code)
  }
  return payload as T
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

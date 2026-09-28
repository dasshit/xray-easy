import { APIError } from '../application/errors'
import type { ZodType } from 'zod'

export { APIError } from '../application/errors'

export async function request(url: string, options?: RequestInit): Promise<unknown> {
  const response = await fetch(url, { headers: { 'Content-Type': 'application/json' }, ...options })
  const payload: unknown = await response.json().catch(() => ({}))
  if (!response.ok) {
    const errorPayload = isRecord(payload) ? payload : {}
    const message = typeof errorPayload.error === 'string' ? errorPayload.error : `HTTP ${response.status}`
    const code = typeof errorPayload.code === 'string' ? errorPayload.code : undefined
    throw new APIError(message, code)
  }
  return payload
}

export function parseResponse<T>(payload: unknown, schema: ZodType<T>): T {
  const result = schema.safeParse(payload)
  if (!result.success) throw new APIError('The server returned an invalid response', 'invalid_response')
  return result.data
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

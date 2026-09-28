import { APIError } from '../application/errors'
import type { ZodType } from 'zod'

export { APIError } from '../application/errors'

/**
 * Send a JSON API request and return its decoded response payload.
 * @param url - The API path or URL to request.
 * @param options - Optional fetch settings such as method and request body.
 * @returns The decoded response payload, left unknown until validated.
 * @rejects {APIError} When the server responds unsuccessfully; network failures also reject.
 */
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

/**
 * Validate an unknown server payload against its runtime schema.
 * @param payload - The untrusted response payload.
 * @param schema - The Zod schema that defines the expected response shape.
 * @returns The validated payload with the schema output type.
 * @throws {APIError} When the payload does not match the schema.
 */
export function parseResponse<T>(payload: unknown, schema: ZodType<T>): T {
  const result = schema.safeParse(payload)
  if (!result.success) throw new APIError('The server returned an invalid response', 'invalid_response')
  return result.data
}

/**
 * Check whether a value is a non-null object record.
 * @param value - The value to inspect.
 * @returns True when the value is an object and is not null.
 */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

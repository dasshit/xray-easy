import { APIError } from '../application/errors'

export { APIError } from '../application/errors'

export async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(url, { headers: { 'Content-Type': 'application/json' }, ...options })
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) throw new APIError(payload.error || `HTTP ${response.status}`, payload.code)
  return payload as T
}

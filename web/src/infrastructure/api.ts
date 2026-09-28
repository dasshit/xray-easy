export class APIError extends Error {
  code?: string

  constructor(message: string, code?: string) {
    super(message)
    this.name = 'APIError'
    this.code = code
  }
}

export async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(url, { headers: { 'Content-Type': 'application/json' }, ...options })
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) throw new APIError(payload.error || `HTTP ${response.status}`, payload.code)
  return payload as T
}

export class APIError extends Error {
  code?: string

  constructor(message: string, code?: string) {
    super(message)
    this.name = 'APIError'
    if (code !== undefined) this.code = code
  }
}

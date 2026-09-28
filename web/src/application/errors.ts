export class APIError extends Error {
  code?: string

  constructor(message: string, code?: string) {
    super(message)
    this.name = 'APIError'
    this.code = code
  }
}

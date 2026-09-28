export class APIError extends Error {
  code?: string

  /**
   * Create an API error with an optional server-provided code.
   * @param message - The human-readable error message.
   * @param code - The optional machine-readable error code.
   */
  constructor(message: string, code?: string) {
    super(message)
    this.name = 'APIError'
    if (code !== undefined) this.code = code
  }
}

export class APIError extends Error {
  /**
   * Machine-readable code from the server, when one is supplied.
   * The UI handles `totp_required` specially; codes such as `validation_error`, `settings_incomplete`, and
   * `confirmation_expired` are shown as operation failures. The server may add codes, so callers must preserve unknown strings.
   */
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

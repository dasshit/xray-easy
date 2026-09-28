export type SetupStatusDto = { initialized: boolean; public_port?: number }
export type AdminDto = { username: string; totp_enabled?: boolean; recovery_codes_remaining?: number }
export type ClientDto = {
  id: string
  name: string
  enabled: boolean
  revoked: boolean
  fingerprint?: string
  online: boolean
  last_seen?: string
  upload_bytes: number
  download_bytes: number
}
export type TOTPStatusDto = { enabled: boolean; recovery_codes_remaining: number }
export type TOTPSetupDto = {
  setup_token: string
  secret: string
  otpauth_uri: string
  qr_png?: string
  recovery_codes: string[]
  expires_in: number
}
export type ProfileDeliveryDto = { client_id: string; uri: string; json: unknown }
export type SettingsDto = {
  public_host: string
  public_port: number
  reality_target: string
  reality_sni: string
  client_fingerprint: string
  protocol: string
  network: string
  security: string
  flow: string
}
export type SettingsChangeDto = {
  change_id: string
  expires_in: number
  expected_confirmation: string
  requires_confirmation: boolean
  diff: { field: string; from: string; to: string }[]
  consequences: string[]
  revoked_clients: number
  settings: SettingsDto
}
export type NodeStatusDto = {
  state: string
  restart_count: number
  last_error?: string
  last_exit?: string
  stats_last_error?: string
  supervisor_error?: string
}
export type DiagnosticEntryDto = { at: string; component: string; level: string; message: string }

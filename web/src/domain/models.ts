export type SetupStatus = { initialized: boolean; public_port?: number }
export type Admin = { username: string; totp_enabled?: boolean; recovery_codes_remaining?: number }
export type Client = {
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
export type TOTPStatus = { enabled: boolean; recovery_codes_remaining: number }
export type TOTPSetup = { setup_token: string; secret: string; otpauth_uri: string; qr_png?: string; recovery_codes: string[]; expires_in: number }
export type Settings = {
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
export type SettingsDiff = { field: string; from: string; to: string }
export type SettingsChange = {
  change_id: string
  expires_in: number
  expected_confirmation: string
  requires_confirmation: boolean
  diff: SettingsDiff[]
  consequences: string[]
  revoked_clients: number
  settings: Settings
  confirmation: string
}
export type NodeStatus = { state: string; restart_count: number; last_error?: string; last_exit?: string; stats_last_error?: string; supervisor_error?: string }
export type DiagnosticEntry = { at: string; component: string; level: string; message: string }
export type Section = 'profiles' | 'settings' | 'diagnostics' | 'security'
export type ClientActionType = 'enable' | 'disable' | 'revoke'
export type ClientAction = { client: Client; action: ClientActionType } | null
export type Theme = 'light' | 'dark'

export function clientActionFor(client: Client): ClientActionType | null {
  if (client.revoked) return null
  return client.enabled ? 'disable' : 'enable'
}

export function canEnableClient(client: Client): boolean {
  return !client.revoked && !client.enabled
}

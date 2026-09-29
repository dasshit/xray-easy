/** A managed device profile and its current Xray state. */
export type Client = {
  id: string
  name: string
  /** Credential-bearing protocol profile created for this device record. */
  protocol: ClientProtocol
  /** Protocols with credentials attached to this profile. */
  protocols: ClientProtocol[]
  /** Access state when the profile includes a VLESS inbound. */
  vless?: ClientProtocolAccess
  /** Access state when the profile includes a Hysteria 2 inbound. */
  hysteria2?: ClientProtocolAccess
  /** Whether the profile is enabled in the active Xray configuration. */
  enabled: boolean
  /** Whether the profile was permanently revoked and cannot be re-enabled. */
  revoked: boolean
  fingerprint?: string
  /** Whether Xray has seen traffic from this device in the last five minutes. */
  online: boolean
  /** RFC 3339 timestamp of the last observed traffic, when available. */
  lastSeen?: string
  /** Cumulative uploaded traffic in bytes; totals are retained across Xray restarts. */
  uploadBytes: number
  /** Cumulative downloaded traffic in bytes; totals are retained across Xray restarts. */
  downloadBytes: number
}

/** Protocols supported by a device profile, including migrated combined profiles. */
export type ClientProtocol = 'vless' | 'hysteria2' | 'legacy_dual'

/** Enabled and revoked state for one protocol access. */
export type ClientProtocolAccess = { enabled: boolean; revoked: boolean }

/** Log verbosity supported by Xray's server log configuration. */
export type XrayLogLevel = 'debug' | 'info' | 'warning' | 'error' | 'none'

/** Active public endpoint and VLESS + REALITY connection preset. */
export type Settings = {
  publicHost: string
  publicPort: number
  realityTarget: string
  realitySni: string
  clientFingerprint: string
  logLevel: XrayLogLevel
  protocol: string
  network: string
  security: string
  flow: string
}

/** One changed setting in a pending settings preview. */
export type SettingsDiff = { field: string; from: string; to: string }

/** Reviewed settings update awaiting confirmation and application. */
export type SettingsChange = {
  changeId: string
  /** Time remaining before this preview expires, in seconds. */
  expiresIn: number
  /** Exact phrase the administrator must enter when confirmation is required. */
  expectedConfirmation: string
  requiresConfirmation: boolean
  diff: SettingsDiff[]
  consequences: string[]
  /** Existing profile count reported by the preview; profiles are revoked only for changes requiring confirmation. */
  revokedClients: number
  settings: Settings
  /** Phrase entered by the administrator before applying the preview. */
  confirmation: string
}

/** Action available for a device profile in the UI. */
export type ClientActionType = 'enable' | 'disable' | 'revoke'

/** Device selected for a pending action, or null when no action is open. */
export type ClientAction = { client: Client; action: ClientActionType } | null

/**
 * Determine the next enable or disable action allowed for a device.
 * @param client - The device whose current state determines the action.
 * @returns The allowed action, or null when the device is revoked.
 */
export function clientActionFor(client: Client): ClientActionType | null {
  if (client.revoked) return null
  return client.enabled ? 'disable' : 'enable'
}

/**
 * Check whether a device may be enabled.
 * @param client - The device to inspect.
 * @returns True when the device is neither revoked nor already enabled.
 */
export function canEnableClient(client: Client): boolean {
  return !client.revoked && !client.enabled
}

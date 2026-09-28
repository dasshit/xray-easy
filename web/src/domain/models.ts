export type Client = {
  id: string
  name: string
  enabled: boolean
  revoked: boolean
  fingerprint?: string
  online: boolean
  lastSeen?: string
  uploadBytes: number
  downloadBytes: number
}

export type Settings = {
  publicHost: string
  publicPort: number
  realityTarget: string
  realitySni: string
  clientFingerprint: string
  protocol: string
  network: string
  security: string
  flow: string
}

export type SettingsDiff = { field: string; from: string; to: string }
export type SettingsChange = {
  changeId: string
  expiresIn: number
  expectedConfirmation: string
  requiresConfirmation: boolean
  diff: SettingsDiff[]
  consequences: string[]
  revokedClients: number
  settings: Settings
  confirmation: string
}

export type ClientActionType = 'enable' | 'disable' | 'revoke'
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

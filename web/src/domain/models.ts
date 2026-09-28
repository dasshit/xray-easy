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

export function clientActionFor(client: Client): ClientActionType | null {
  if (client.revoked) return null
  return client.enabled ? 'disable' : 'enable'
}

export function canEnableClient(client: Client): boolean {
  return !client.revoked && !client.enabled
}

export type SetupStatus = { initialized: boolean; publicPort?: number }
export type InitializeSetupCommand = {
  username: string
  password: string
  publicHost: string
  publicPort: number
  realityTarget: string
  realitySni: string
}
export type Admin = { username: string; totpEnabled?: boolean; recoveryCodesRemaining?: number }
export type TOTPStatus = { enabled: boolean; recoveryCodesRemaining: number }
export type TOTPSetup = {
  setupToken: string
  secret: string
  otpauthUri: string
  qrPng?: string
  recoveryCodes: string[]
  expiresIn: number
}
export type ProfileDelivery = { clientId: string; uri: string; json: unknown }
export type SettingsPreviewCommand = {
  publicHost: string
  realityTarget: string
  realitySni: string
  clientFingerprint: string
  rotatePrivateKey: boolean
}
export type NodeStatus = {
  state: string
  restartCount: number
  lastError?: string
  lastExit?: string
  statsLastError?: string
  supervisorError?: string
}
export type DiagnosticEntry = { at: string; component: string; level: string; message: string }

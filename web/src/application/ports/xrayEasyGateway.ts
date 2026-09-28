import type {
  Admin,
  DiagnosticEntry,
  InitializeSetupCommand,
  NodeStatus,
  ProfileDelivery,
  SettingsPreviewCommand,
  SetupStatus,
  TOTPSetup,
  TOTPStatus,
} from '../models'
import type { Client, ClientActionType, Settings, SettingsChange } from '../../domain/models'

export interface XrayEventCallbacks {
  onStats: () => void
  onStatus: () => void
  onError: () => void
}

export interface EventSubscription {
  close(): void
}

export interface XrayEasyGateway {
  setup: {
    status(): Promise<SetupStatus>
    initialize(input: InitializeSetupCommand): Promise<void>
  }
  auth: {
    current(): Promise<Admin>
    login(username: string, password: string): Promise<Admin>
    loginWithTOTP(username: string, password: string, code: string): Promise<Admin>
    loginWithRecoveryCode(username: string, password: string, code: string): Promise<Admin>
    logout(): Promise<void>
    logoutAll(): Promise<void>
    totpStatus(): Promise<TOTPStatus>
    beginTOTPSetup(): Promise<TOTPSetup>
    enableTOTP(setupToken: string, code: string): Promise<void>
    disableTOTP(password: string, code: string): Promise<void>
  }
  clients: {
    list(): Promise<Client[]>
    create(name: string, fingerprint?: string): Promise<Client>
    profile(clientId: string): Promise<ProfileDelivery>
    setAction(clientId: string, action: ClientActionType): Promise<Client>
    profileQrUrl(clientId: string): string
    profileJsonUrl(clientId: string): string
  }
  settings: {
    get(): Promise<Settings>
    preview(input: SettingsPreviewCommand): Promise<Omit<SettingsChange, 'confirmation'>>
    apply(changeId: string, confirmation: string): Promise<void>
  }
  backups: {
    create(): Promise<{ name: string }>
  }
  diagnostics: {
    status(): Promise<NodeStatus>
    logs(component: string, limit?: number): Promise<DiagnosticEntry[]>
  }
  events: {
    connect(callbacks: XrayEventCallbacks): EventSubscription
  }
}

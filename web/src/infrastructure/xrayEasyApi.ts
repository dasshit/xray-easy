import type { Admin, DiagnosticEntry, InitializeSetupCommand, NodeStatus, ProfileDelivery, SettingsPreviewCommand, SetupStatus, TOTPSetup, TOTPStatus } from '../application/models'
import type { XrayEasyGateway } from '../application/ports/xrayEasyGateway'
import type { Client, ClientActionType, Settings, SettingsChange } from '../domain/models'
import { request } from './api'
import { connectXrayEvents } from './events'
import type {
  AdminDto,
  ClientDto,
  DiagnosticEntryDto,
  NodeStatusDto,
  ProfileDeliveryDto,
  SettingsChangeDto,
  SettingsDto,
  SetupStatusDto,
  TOTPSetupDto,
  TOTPStatusDto,
} from './api-contracts'

export type JsonRequester = <T>(url: string, options?: RequestInit) => Promise<T>

function post(body?: unknown): RequestInit {
  return { method: 'POST', ...(body === undefined ? {} : { body: JSON.stringify(body) }) }
}

function mapAdmin(dto: AdminDto): Admin {
  return {
    username: dto.username,
    ...(dto.totp_enabled === undefined ? {} : { totpEnabled: dto.totp_enabled }),
    ...(dto.recovery_codes_remaining === undefined ? {} : { recoveryCodesRemaining: dto.recovery_codes_remaining }),
  }
}

function mapClient(dto: ClientDto): Client {
  return {
    id: dto.id,
    name: dto.name,
    enabled: dto.enabled,
    revoked: dto.revoked,
    online: dto.online,
    uploadBytes: dto.upload_bytes,
    downloadBytes: dto.download_bytes,
    ...(dto.fingerprint === undefined ? {} : { fingerprint: dto.fingerprint }),
    ...(dto.last_seen === undefined ? {} : { lastSeen: dto.last_seen }),
  }
}

function mapSettings(dto: SettingsDto): Settings {
  return {
    publicHost: dto.public_host,
    publicPort: dto.public_port,
    realityTarget: dto.reality_target,
    realitySni: dto.reality_sni,
    clientFingerprint: dto.client_fingerprint,
    protocol: dto.protocol,
    network: dto.network,
    security: dto.security,
    flow: dto.flow,
  }
}

function mapSettingsChange(dto: SettingsChangeDto): Omit<SettingsChange, 'confirmation'> {
  return {
    changeId: dto.change_id,
    expiresIn: dto.expires_in,
    expectedConfirmation: dto.expected_confirmation,
    requiresConfirmation: dto.requires_confirmation,
    diff: dto.diff,
    consequences: dto.consequences,
    revokedClients: dto.revoked_clients,
    settings: mapSettings(dto.settings),
  }
}

function mapTOTPSetup(dto: TOTPSetupDto): TOTPSetup {
  return {
    setupToken: dto.setup_token,
    secret: dto.secret,
    otpauthUri: dto.otpauth_uri,
    recoveryCodes: dto.recovery_codes,
    expiresIn: dto.expires_in,
    ...(dto.qr_png === undefined ? {} : { qrPng: dto.qr_png }),
  }
}

function mapNodeStatus(dto: NodeStatusDto): NodeStatus {
  return {
    state: dto.state,
    restartCount: dto.restart_count,
    ...(dto.last_error === undefined ? {} : { lastError: dto.last_error }),
    ...(dto.last_exit === undefined ? {} : { lastExit: dto.last_exit }),
    ...(dto.stats_last_error === undefined ? {} : { statsLastError: dto.stats_last_error }),
    ...(dto.supervisor_error === undefined ? {} : { supervisorError: dto.supervisor_error }),
  }
}

function mapDiagnostic(dto: DiagnosticEntryDto): DiagnosticEntry {
  return { at: dto.at, component: dto.component, level: dto.level, message: dto.message }
}

export function createXrayEasyApi(send: JsonRequester = request): XrayEasyGateway {
  const sendVoid = async (url: string, options?: RequestInit): Promise<void> => {
    await send<unknown>(url, options)
  }

  return {
    setup: {
      status: async (): Promise<SetupStatus> => {
        const dto = await send<SetupStatusDto>('/api/setup/status')
        return {
          initialized: dto.initialized,
          ...(dto.public_port === undefined ? {} : { publicPort: dto.public_port }),
        }
      },
      initialize: (input: InitializeSetupCommand): Promise<void> => sendVoid('/api/setup/initialize', {
        method: 'POST',
        body: JSON.stringify({
          username: input.username,
          password: input.password,
          public_host: input.publicHost,
          public_port: input.publicPort,
          reality_target: input.realityTarget,
          reality_sni: input.realitySni,
        }),
      }),
    },
    auth: {
      current: async (): Promise<Admin> => mapAdmin(await send<AdminDto>('/api/me')),
      login: async (username: string, password: string): Promise<Admin> => mapAdmin(await send<AdminDto>('/api/auth/login', {
        method: 'POST', body: JSON.stringify({ username, password }),
      })),
      loginWithTOTP: async (username: string, password: string, totpCode: string): Promise<Admin> => mapAdmin(await send<AdminDto>('/api/auth/login/totp', {
        method: 'POST', body: JSON.stringify({ username, password, totp_code: totpCode }),
      })),
      loginWithRecoveryCode: async (username: string, password: string, recoveryCode: string): Promise<Admin> => mapAdmin(await send<AdminDto>('/api/auth/login/recovery', {
        method: 'POST', body: JSON.stringify({ username, password, recovery_code: recoveryCode }),
      })),
      logout: (): Promise<void> => sendVoid('/api/auth/logout', post()),
      logoutAll: (): Promise<void> => sendVoid('/api/auth/logout-all', post()),
      totpStatus: async (): Promise<TOTPStatus> => {
        const dto = await send<TOTPStatusDto>('/api/auth/totp/status')
        return { enabled: dto.enabled, recoveryCodesRemaining: dto.recovery_codes_remaining }
      },
      beginTOTPSetup: async (): Promise<TOTPSetup> => mapTOTPSetup(await send<TOTPSetupDto>('/api/auth/totp/setup', post())),
      enableTOTP: (setupToken: string, code: string): Promise<void> => sendVoid('/api/auth/totp/enable', post({ setup_token: setupToken, code })),
      disableTOTP: (password: string, code: string): Promise<void> => sendVoid('/api/auth/totp/disable', post({ password, code })),
    },
    clients: {
      list: async (): Promise<Client[]> => (await send<ClientDto[]>('/api/clients')).map(mapClient),
      create: async (name: string, fingerprint?: string): Promise<Client> => mapClient(await send<ClientDto>('/api/clients', {
        method: 'POST', body: JSON.stringify({
          name,
          ...(fingerprint === undefined || fingerprint === '' ? {} : { fingerprint }),
        }),
      })),
      profile: async (clientId: string): Promise<ProfileDelivery> => {
        const dto = await send<ProfileDeliveryDto>(`/api/clients/${encodeURIComponent(clientId)}/profile?format=uri`)
        return { clientId: dto.client_id, uri: dto.uri, json: dto.json }
      },
      setAction: async (clientId: string, action: ClientActionType): Promise<Client> => mapClient(
        await send<ClientDto>(`/api/clients/${encodeURIComponent(clientId)}/${action}`, post()),
      ),
      profileQrUrl: (clientId: string): string => `/api/clients/${encodeURIComponent(clientId)}/profile?format=qr`,
      profileJsonUrl: (clientId: string): string => `/api/clients/${encodeURIComponent(clientId)}/profile?format=json`,
    },
    settings: {
      get: async (): Promise<Settings> => mapSettings(await send<SettingsDto>('/api/settings')),
      preview: async (input: SettingsPreviewCommand): Promise<Omit<SettingsChange, 'confirmation'>> => mapSettingsChange(await send<SettingsChangeDto>('/api/settings', {
        method: 'PATCH',
        body: JSON.stringify({
          public_host: input.publicHost,
          reality_target: input.realityTarget,
          reality_sni: input.realitySni,
          client_fingerprint: input.clientFingerprint,
          rotate_private_key: input.rotatePrivateKey,
        }),
      })),
      apply: (changeId: string, confirmation: string): Promise<void> => sendVoid('/api/settings/apply', post({ change_id: changeId, confirmation })),
    },
    backups: {
      create: (): Promise<{ name: string }> => send('/api/backups', post()),
    },
    diagnostics: {
      status: async (): Promise<NodeStatus> => mapNodeStatus(await send<NodeStatusDto>('/api/status')),
      logs: async (component: string, limit = 100): Promise<DiagnosticEntry[]> => {
        const result = await send<{ entries: DiagnosticEntryDto[] }>(`/api/logs?component=${encodeURIComponent(component)}&limit=${limit}`)
        return result.entries.map(mapDiagnostic)
      },
    },
    events: {
      connect: connectXrayEvents,
    },
  }
}

export const xrayEasyApi = createXrayEasyApi()

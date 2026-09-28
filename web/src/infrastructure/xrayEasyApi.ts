import type { Admin, DiagnosticEntry, InitializeSetupCommand, NodeStatus, ProfileDelivery, SettingsPreviewCommand, SetupStatus, TOTPSetup, TOTPStatus } from '../application/models'
import type { XrayEasyGateway } from '../application/ports/xrayEasyGateway'
import type { Client, ClientActionType, Settings, SettingsChange } from '../domain/models'
import { parseResponse, request } from './api'
import { connectXrayEvents } from './events'
import type { ZodType } from 'zod'
import {
  AdminDtoSchema,
  BackupDtoSchema,
  ClientDtoSchema,
  DiagnosticEntriesDtoSchema,
  NodeStatusDtoSchema,
  ProfileDeliveryDtoSchema,
  SettingsChangeDtoSchema,
  SettingsDtoSchema,
  SetupStatusDtoSchema,
  TOTPSetupDtoSchema,
  TOTPStatusDtoSchema,
} from './api-contracts'
import type {
  AdminDto,
  BackupDto,
  ClientDto,
  DiagnosticEntryDto,
  DiagnosticEntriesDto,
  NodeStatusDto,
  SettingsChangeDto,
  SettingsDto,
  TOTPSetupDto,
} from './api-contracts'

export type JsonRequester = (url: string, options?: RequestInit) => Promise<unknown>

function post(body?: unknown): RequestInit {
  return { method: 'POST', ...(body === undefined ? {} : { body: JSON.stringify(body) }) }
}

async function sendDto<T>(send: JsonRequester, url: string, schema: ZodType<T>, options?: RequestInit): Promise<T> {
  return parseResponse(await send(url, options), schema)
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
    await send(url, options)
  }

  return {
    setup: {
      status: async (): Promise<SetupStatus> => {
        const dto = await sendDto(send, '/api/setup/status', SetupStatusDtoSchema)
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
      current: async (): Promise<Admin> => mapAdmin(await sendDto(send, '/api/me', AdminDtoSchema)),
      login: async (username: string, password: string): Promise<Admin> => mapAdmin(await sendDto(send, '/api/auth/login', AdminDtoSchema, {
        method: 'POST', body: JSON.stringify({ username, password }),
      })),
      loginWithTOTP: async (username: string, password: string, totpCode: string): Promise<Admin> => mapAdmin(await sendDto(send, '/api/auth/login/totp', AdminDtoSchema, {
        method: 'POST', body: JSON.stringify({ username, password, totp_code: totpCode }),
      })),
      loginWithRecoveryCode: async (username: string, password: string, recoveryCode: string): Promise<Admin> => mapAdmin(await sendDto(send, '/api/auth/login/recovery', AdminDtoSchema, {
        method: 'POST', body: JSON.stringify({ username, password, recovery_code: recoveryCode }),
      })),
      logout: (): Promise<void> => sendVoid('/api/auth/logout', post()),
      logoutAll: (): Promise<void> => sendVoid('/api/auth/logout-all', post()),
      totpStatus: async (): Promise<TOTPStatus> => {
        const dto = await sendDto(send, '/api/auth/totp/status', TOTPStatusDtoSchema)
        return { enabled: dto.enabled, recoveryCodesRemaining: dto.recovery_codes_remaining }
      },
      beginTOTPSetup: async (): Promise<TOTPSetup> => mapTOTPSetup(await sendDto(send, '/api/auth/totp/setup', TOTPSetupDtoSchema, post())),
      enableTOTP: (setupToken: string, code: string): Promise<void> => sendVoid('/api/auth/totp/enable', post({ setup_token: setupToken, code })),
      disableTOTP: (password: string, code: string): Promise<void> => sendVoid('/api/auth/totp/disable', post({ password, code })),
    },
    clients: {
      list: async (): Promise<Client[]> => (await sendDto(send, '/api/clients', ClientDtoSchema.array())).map(mapClient),
      create: async (name: string, fingerprint?: string): Promise<Client> => mapClient(await sendDto(send, '/api/clients', ClientDtoSchema, {
        method: 'POST', body: JSON.stringify({
          name,
          ...(fingerprint === undefined || fingerprint === '' ? {} : { fingerprint }),
        }),
      })),
      profile: async (clientId: string): Promise<ProfileDelivery> => {
        const dto = await sendDto(send, `/api/clients/${encodeURIComponent(clientId)}/profile?format=uri`, ProfileDeliveryDtoSchema)
        return { clientId: dto.client_id, uri: dto.uri, json: dto.json }
      },
      setAction: async (clientId: string, action: ClientActionType): Promise<Client> => mapClient(
        await sendDto(send, `/api/clients/${encodeURIComponent(clientId)}/${action}`, ClientDtoSchema, post()),
      ),
      profileQrUrl: (clientId: string): string => `/api/clients/${encodeURIComponent(clientId)}/profile?format=qr`,
      profileJsonUrl: (clientId: string): string => `/api/clients/${encodeURIComponent(clientId)}/profile?format=json`,
    },
    settings: {
      get: async (): Promise<Settings> => mapSettings(await sendDto(send, '/api/settings', SettingsDtoSchema)),
      preview: async (input: SettingsPreviewCommand): Promise<Omit<SettingsChange, 'confirmation'>> => mapSettingsChange(await sendDto(send, '/api/settings', SettingsChangeDtoSchema, {
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
      create: async (): Promise<{ name: string }> => {
        const dto: BackupDto = await sendDto(send, '/api/backups', BackupDtoSchema, post())
        return dto
      },
    },
    diagnostics: {
      status: async (): Promise<NodeStatus> => mapNodeStatus(await sendDto(send, '/api/status', NodeStatusDtoSchema)),
      logs: async (component: string, limit = 100): Promise<DiagnosticEntry[]> => {
        const result: DiagnosticEntriesDto = await sendDto(send, `/api/logs?component=${encodeURIComponent(component)}&limit=${limit}`, DiagnosticEntriesDtoSchema)
        return result.entries.map(mapDiagnostic)
      },
    },
    events: {
      connect: connectXrayEvents,
    },
  }
}

export const xrayEasyApi = createXrayEasyApi()

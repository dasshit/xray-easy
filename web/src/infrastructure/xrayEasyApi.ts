import type { Admin, CreateClientCommand, DiagnosticEntry, HysteriaCertificateInfo, HysteriaCertificateUpload, HysteriaSettings, HysteriaSettingsCommand, HysteriaSettingsPreview, InitializeSetupCommand, NodeStatus, ProfileDelivery, SettingsPreviewCommand, SetupStatus, TOTPSetup, TOTPStatus } from '../application/models'
import type { XrayEasyGateway } from '../application/ports/xrayEasyGateway'
import type { AmneziaWGStatus, Client, ClientActionType, Settings, SettingsChange } from '../domain/models'
import { parseResponse, request } from './api'
import { connectXrayEvents } from './events'
import type { ZodType } from 'zod'
import {
  AdminDtoSchema,
  AmneziaWGStatusDtoSchema,
  BackupDtoSchema,
  ClientDtoSchema,
  DiagnosticEntriesDtoSchema,
  HysteriaCertificateUploadDtoSchema,
  HysteriaSettingsDtoSchema,
  HysteriaSettingsPreviewDtoSchema,
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
  AmneziaWGStatusDto,
  BackupDto,
  ClientDto,
  DiagnosticEntryDto,
  DiagnosticEntriesDto,
  HysteriaCertificateInfoDto,
  HysteriaCertificateUploadDto,
  HysteriaSettingsDto,
  HysteriaSettingsPreviewDto,
  NodeStatusDto,
  SettingsChangeDto,
  SettingsDto,
  TOTPSetupDto,
} from './api-contracts'

export type JsonRequester = (url: string, options?: RequestInit) => Promise<unknown>

/**
 * Build fetch options for a JSON POST request.
 * @param body - Optional request data to JSON-encode.
 * @returns POST request options with a JSON body when provided.
 */
function post(body?: unknown): RequestInit {
  return { method: 'POST', ...(body === undefined ? {} : { body: JSON.stringify(body) }) }
}

/**
 * Send a request and validate its response using the supplied schema.
 * @param send - The JSON requester used to send the request.
 * @param url - The API path to request.
 * @param schema - The schema expected for the response.
 * @param options - Optional fetch settings for the request.
 * @returns The validated response value.
 * @rejects {Error} When the request fails or its response does not match the schema.
 */
async function sendDto<T>(send: JsonRequester, url: string, schema: ZodType<T>, options?: RequestInit): Promise<T> {
  return parseResponse(await send(url, options), schema)
}

/**
 * Convert the administrator API response into the application model.
 * @param dto - The validated administrator response.
 * @returns The administrator domain model.
 */
function mapAdmin(dto: AdminDto): Admin {
  return {
    username: dto.username,
    ...(dto.totp_enabled === undefined ? {} : { totpEnabled: dto.totp_enabled }),
    ...(dto.recovery_codes_remaining === undefined ? {} : { recoveryCodesRemaining: dto.recovery_codes_remaining }),
  }
}

/**
 * Convert a device API response into the application model.
 * @param dto - The validated device response.
 * @returns The device domain model.
 */
function mapClient(dto: ClientDto): Client {
  return {
    id: dto.id,
    name: dto.name,
    protocol: dto.protocol,
    protocols: dto.protocols,
    ...(dto.vless === undefined ? {} : { vless: dto.vless }),
    ...(dto.hysteria2 === undefined ? {} : { hysteria2: dto.hysteria2 }),
    ...(dto.vmess === undefined ? {} : { vmess: dto.vmess }),
    ...(dto.shadowsocks === undefined ? {} : { shadowsocks: dto.shadowsocks }),
    ...(dto.trojan === undefined ? {} : { trojan: dto.trojan }),
    enabled: dto.enabled,
    revoked: dto.revoked,
    online: dto.online,
    uploadBytes: dto.upload_bytes,
    downloadBytes: dto.download_bytes,
    ...(dto.source_ips === undefined ? {} : { sourceIPs: dto.source_ips }),
    uploadBytesPerSecond: dto.upload_bytes_per_second,
    downloadBytesPerSecond: dto.download_bytes_per_second,
    ...(dto.fingerprint === undefined ? {} : { fingerprint: dto.fingerprint }),
    ...(dto.last_seen === undefined ? {} : { lastSeen: dto.last_seen }),
  }
}

/**
 * Convert the settings API response into the application model.
 * @param dto - The validated settings response.
 * @returns The settings domain model.
 */
function mapSettings(dto: SettingsDto): Settings {
  return {
    publicHost: dto.public_host,
    publicPort: dto.public_port,
    vmessPublicPort: dto.vmess_public_port,
    shadowsocksEnabled: dto.shadowsocks_enabled,
    shadowsocksPublicPort: dto.shadowsocks_public_port,
    shadowsocksMethod: dto.shadowsocks_method,
    shadowsocksNetwork: dto.shadowsocks_network,
    trojanEnabled: dto.trojan_enabled,
    trojanPublicPort: dto.trojan_public_port,
    realityTarget: dto.reality_target,
    realitySni: dto.reality_sni,
    clientFingerprint: dto.client_fingerprint,
    logLevel: dto.log_level,
    protocol: dto.protocol,
    network: dto.network,
    security: dto.security,
    flow: dto.flow,
  }
}

/**
 * Convert a settings preview response into the application model.
 * @param dto - The validated settings-change response.
 * @returns The preview and consequences without the UI confirmation field.
 */
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

/**
 * Convert certificate metadata into the application model.
 * @param dto - The validated public certificate metadata.
 * @returns The certificate details without key material.
 */
function mapHysteriaCertificate(dto: HysteriaCertificateInfoDto): HysteriaCertificateInfo {
  return {
    subject: dto.subject,
    issuer: dto.issuer,
    dnsNames: dto.dns_names,
    ipAddresses: dto.ip_addresses,
    notBefore: dto.not_before,
    notAfter: dto.not_after,
    fingerprint: dto.fingerprint,
  }
}

/**
 * Convert the Hysteria 2 status DTO into the application model.
 * @param dto - The validated Hysteria settings response.
 * @returns The current transport state and optional public certificate metadata.
 */
function mapHysteriaSettings(dto: HysteriaSettingsDto): HysteriaSettings {
  return {
    enabled: dto.enabled,
    state: dto.state,
    host: dto.host,
    udpPort: dto.udp_port,
    tlsMode: dto.tls_mode,
    tlsServerName: dto.tls_server_name,
    udpIdleTimeout: dto.udp_idle_timeout,
    masqueradeType: dto.masquerade_type,
    insecureUri: dto.insecure_uri,
    ...(dto.tls_cert_ip === undefined ? {} : { tlsCertIp: dto.tls_cert_ip }),
    ...(dto.certificate_id === undefined ? {} : { certificateId: dto.certificate_id }),
    ...(dto.certificate === undefined ? {} : { certificate: mapHysteriaCertificate(dto.certificate) }),
    ...(dto.certificate_error === undefined ? {} : { certificateError: dto.certificate_error }),
    ...(dto.runtime_error === undefined ? {} : { runtimeError: dto.runtime_error }),
    ...(dto.masquerade_string === undefined ? {} : { masqueradeString: dto.masquerade_string }),
  }
}

/** Convert an AmneziaWG status response into the application model.
 * @param dto - The validated status response.
 * @returns The service availability and listener details.
 */
function mapAmneziaWGStatus(dto: AmneziaWGStatusDto): AmneziaWGStatus {
  return {
    enabled: dto.enabled,
    available: dto.available,
    running: dto.running,
    ...(dto.public_key === undefined ? {} : { publicKey: dto.public_key }),
    ...(dto.public_host === undefined ? {} : { publicHost: dto.public_host }),
    ...(dto.public_port === undefined ? {} : { publicPort: dto.public_port }),
    ...(dto.listen_port === undefined ? {} : { listenPort: dto.listen_port }),
    ...(dto.peer_count === undefined ? {} : { peerCount: dto.peer_count }),
    ...(dto.ipv4_network === undefined ? {} : { ipv4Network: dto.ipv4_network }),
    ...(dto.ipv6_network === undefined ? {} : { ipv6Network: dto.ipv6_network }),
    ...(dto.service_version === undefined ? {} : { serviceVersion: dto.service_version }),
  }
}

/**
 * Convert the certificate staging response into the application model.
 * @param dto - The validated certificate upload response.
 * @returns The immutable certificate version and public metadata.
 */
function mapHysteriaCertificateUpload(dto: HysteriaCertificateUploadDto): HysteriaCertificateUpload {
  return { certificateId: dto.certificate_id, certificate: mapHysteriaCertificate(dto.certificate) }
}

/**
 * Convert the Hysteria settings preview DTO into the application result.
 * @param dto - The validated preview response.
 * @returns The review information, or current settings when no change is needed.
 */
function mapHysteriaPreview(dto: HysteriaSettingsPreviewDto): HysteriaSettingsPreview {
  const settings = mapHysteriaSettings(dto.settings)
  if (!dto.changed) return { changed: false, settings }
  return {
    changed: true,
    changeId: dto.change_id,
    expiresIn: dto.expires_in,
    expectedConfirmation: dto.expected_confirmation,
    requiresConfirmation: dto.requires_confirmation,
    diff: dto.diff,
    consequences: dto.consequences,
    settings,
  }
}

/**
 * Convert a TOTP enrollment response into the application model.
 * @param dto - The validated TOTP setup response.
 * @returns The TOTP setup details, including optional QR image data.
 */
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

/**
 * Convert a node status response into the application model.
 * @param dto - The validated node status response.
 * @returns The node status model.
 */
function mapNodeStatus(dto: NodeStatusDto): NodeStatus {
  return {
    state: dto.state,
    ...(dto.xray_version === undefined ? {} : { xrayVersion: dto.xray_version }),
    ...(dto.inbound_tags === undefined ? {} : { inboundTags: dto.inbound_tags }),
    ...(dto.configured_xray_version === undefined ? {} : { configuredXrayVersion: dto.configured_xray_version }),
    ...(dto.xray_version_verified === undefined ? {} : { xrayVersionVerified: dto.xray_version_verified }),
    ...(dto.last_error === undefined ? {} : { lastError: dto.last_error }),
    ...(dto.stats_last_error === undefined ? {} : { statsLastError: dto.stats_last_error }),
    ...(dto.xray_runtime_error === undefined ? {} : { xrayRuntimeError: dto.xray_runtime_error }),
  }
}

/**
 * Convert a diagnostic response into the application model.
 * @param dto - The validated diagnostic entry response.
 * @returns The diagnostic entry model.
 */
function mapDiagnostic(dto: DiagnosticEntryDto): DiagnosticEntry {
  return { at: dto.at, component: dto.component, level: dto.level, message: dto.message }
}

/**
 * Create the application gateway that translates application operations into HTTP requests.
 * @param send - The JSON requester to use; defaults to the shared fetch implementation.
 * @returns The gateway for setup, authentication, devices, settings, backups, diagnostics, and events.
 */
export function createXrayEasyApi(send: JsonRequester = request): XrayEasyGateway {
  /**
   * Send a command whose successful response has no data to return.
   * @param url - The API path to request.
   * @param options - Optional fetch settings for the request.
   * @rejects {Error} When the request fails.
   */
  async function sendVoid(url: string, options?: RequestInit): Promise<void> {
    await send(url, options)
  }

  return {
    setup: {
      status: async (): Promise<SetupStatus> => {
        const dto = await sendDto(send, '/api/setup/status', SetupStatusDtoSchema)
        return {
          initialized: dto.initialized,
          ...(dto.public_port === undefined ? {} : { publicPort: dto.public_port }),
          ...(dto.suggested_public_host === undefined ? {} : { suggestedPublicHost: dto.suggested_public_host }),
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
      changePassword: (currentPassword: string, newPassword: string): Promise<void> => sendVoid('/api/auth/password', post({ current_password: currentPassword, new_password: newPassword })),
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
      create: async (input: CreateClientCommand): Promise<Client> => mapClient(await sendDto(send, '/api/clients', ClientDtoSchema, {
        method: 'POST', body: JSON.stringify({
          name: input.name,
          protocol: input.protocol,
          ...(input.fingerprint === undefined || input.fingerprint === '' ? {} : { fingerprint: input.fingerprint }),
          ...(input.auth === undefined || input.auth === '' ? {} : { auth: input.auth }),
        }),
      })),
      profile: async (clientId: string): Promise<ProfileDelivery> => {
        const dto = await sendDto(send, `/api/clients/${encodeURIComponent(clientId)}/profile?format=uri`, ProfileDeliveryDtoSchema)
        if (dto.protocol === 'vless') return { clientId: dto.client_id, protocol: dto.protocol, uri: dto.uri, json: dto.json }
        if (dto.protocol === 'hysteria2') return { clientId: dto.client_id, protocol: dto.protocol, hysteriaUri: dto.hysteria_uri }
        if (dto.protocol === 'vmess') return { clientId: dto.client_id, protocol: dto.protocol, vmessUri: dto.vmess_uri, json: dto.json }
        if (dto.protocol === 'shadowsocks') return { clientId: dto.client_id, protocol: dto.protocol, ssUri: dto.ss_uri, json: dto.json }
        if (dto.protocol === 'trojan') return { clientId: dto.client_id, protocol: dto.protocol, trojanUri: dto.trojan_uri, json: dto.json }
        if (dto.protocol === 'amneziawg') return { clientId: dto.client_id, protocol: dto.protocol, name: dto.name }
        return {
          clientId: dto.client_id, protocol: dto.protocol,
          ...(dto.uri === undefined ? {} : { uri: dto.uri }),
          ...(dto.hysteria_uri === undefined ? {} : { hysteriaUri: dto.hysteria_uri }),
          ...(dto.json === undefined ? {} : { json: dto.json }),
        }
      },
      setAction: async (clientId: string, action: ClientActionType): Promise<Client | undefined> => {
        if (clientId.startsWith('awg:')) {
          if (action !== 'revoke') throw new Error('AmneziaWG profiles support revoke only')
          await sendVoid(`/api/clients/${encodeURIComponent(clientId)}/revoke`, post())
          return undefined
        }
        return mapClient(await sendDto(send, `/api/clients/${encodeURIComponent(clientId)}/${action}`, ClientDtoSchema, post()))
      },
      profileQrUrl: (clientId: string): string => `/api/clients/${encodeURIComponent(clientId)}/profile?format=qr`,
      profileAmneziaWGUrl: (clientId: string): string => `/api/clients/${encodeURIComponent(clientId)}/profile?format=conf`,
      profileAmneziaWGQrUrl: (clientId: string): string => `/api/clients/${encodeURIComponent(clientId)}/profile?format=qr`,
      profileHysteriaQrUrl: (clientId: string): string => `/api/clients/${encodeURIComponent(clientId)}/profile?format=hysteria-qr`,
      profileVMessQrUrl: (clientId: string): string => `/api/clients/${encodeURIComponent(clientId)}/profile?format=vmess-qr`,
      profileShadowsocksQrUrl: (clientId: string): string => `/api/clients/${encodeURIComponent(clientId)}/profile?format=ss-qr`,
      profileTrojanQrUrl: (clientId: string): string => `/api/clients/${encodeURIComponent(clientId)}/profile?format=trojan-qr`,
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
          log_level: input.logLevel,
          rotate_private_key: input.rotatePrivateKey,
        }),
      })),
      apply: (changeId: string, confirmation: string): Promise<void> => sendVoid('/api/settings/apply', post({ change_id: changeId, confirmation })),
    },
    hysteria: {
      status: async (): Promise<HysteriaSettings> => mapHysteriaSettings(await sendDto(send, '/api/transports/hysteria2', HysteriaSettingsDtoSchema)),
      uploadCertificate: async (fullchain: File, privateKey: File, serverName: string): Promise<HysteriaCertificateUpload> => {
        const form = new FormData()
        form.append('fullchain', fullchain)
        form.append('private_key', privateKey)
        form.append('server_name', serverName)
        return mapHysteriaCertificateUpload(await sendDto(send, '/api/transports/hysteria2/certificate', HysteriaCertificateUploadDtoSchema, {
          method: 'POST', body: form, headers: {},
        }))
      },
      generateCertificate: async (ipv4: string): Promise<HysteriaCertificateUpload> => mapHysteriaCertificateUpload(await sendDto(send, '/api/transports/hysteria2/certificate/mkcert', HysteriaCertificateUploadDtoSchema, post({ ipv4 }))),
      preview: async (input: HysteriaSettingsCommand): Promise<HysteriaSettingsPreview> => mapHysteriaPreview(await sendDto(send, '/api/transports/hysteria2/preview', HysteriaSettingsPreviewDtoSchema, post({
        enabled: input.enabled,
        host: input.host,
        tls_mode: input.tlsMode,
        tls_cert_ip: input.tlsCertIp,
        tls_server_name: input.tlsServerName,
        certificate_id: input.certificateId,
        udp_idle_timeout: input.udpIdleTimeout,
        masquerade_type: input.masqueradeType,
        masquerade_string: input.masqueradeString,
      }))),
      apply: (changeId: string, confirmation: string): Promise<void> => sendVoid('/api/transports/hysteria2/apply', post({ change_id: changeId, confirmation })),
    },
    amneziawg: {
      status: async (): Promise<AmneziaWGStatus> => mapAmneziaWGStatus(await sendDto(send, '/api/transports/amneziawg', AmneziaWGStatusDtoSchema)),
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

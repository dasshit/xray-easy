import { z } from 'zod'

/** Runtime validator for the first-run status response in snake_case wire format. */
export const SetupStatusDtoSchema = z.object({
  initialized: z.boolean(),
  /** Configured public Xray listener port, when the server includes it. */
  public_port: z.number().optional(),
  /** Public IPv4 already selected for a mkcert Hysteria 2 certificate. */
  suggested_public_host: z.string().optional(),
})
/** Wire-format type inferred from {@link SetupStatusDtoSchema}. */
export type SetupStatusDto = z.infer<typeof SetupStatusDtoSchema>

/** Runtime validator for the authenticated administrator response. */
export const AdminDtoSchema = z.object({
  username: z.string(),
  totp_enabled: z.boolean().optional(),
  recovery_codes_remaining: z.number().optional(),
})
/** Wire-format type inferred from {@link AdminDtoSchema}. */
export type AdminDto = z.infer<typeof AdminDtoSchema>

/** Runtime validator for the protocol variants accepted from the server. */
export const ClientProtocolDtoSchema = z.enum(['vless', 'vmess', 'hysteria2', 'legacy_dual'])
/** Wire-format protocol access state. */
export const ClientProtocolAccessDtoSchema = z.object({ enabled: z.boolean(), revoked: z.boolean() })

/** Runtime validator for a profile summary and its protocol-specific access state. */
export const ClientDtoSchema = z.object({
  id: z.string(),
  name: z.string(),
  protocol: ClientProtocolDtoSchema,
  protocols: z.array(ClientProtocolDtoSchema),
  vless: ClientProtocolAccessDtoSchema.optional(),
  hysteria2: ClientProtocolAccessDtoSchema.optional(),
  vmess: ClientProtocolAccessDtoSchema.optional(),
  enabled: z.boolean(),
  revoked: z.boolean(),
  fingerprint: z.string().optional(),
  online: z.boolean(),
  /** RFC 3339 timestamp of the last traffic observed, when available. */
  last_seen: z.string().optional(),
  /** Cumulative uploaded traffic measured in bytes. */
  upload_bytes: z.number(),
  /** Cumulative downloaded traffic measured in bytes. */
  download_bytes: z.number(),
})
/** Wire-format type inferred from {@link ClientDtoSchema}. */
export type ClientDto = z.infer<typeof ClientDtoSchema>

/** Runtime validator for TOTP status and remaining recovery-code count. */
export const TOTPStatusDtoSchema = z.object({
  enabled: z.boolean(),
  recovery_codes_remaining: z.number(),
})
/** Wire-format type inferred from {@link TOTPStatusDtoSchema}. */
export type TOTPStatusDto = z.infer<typeof TOTPStatusDtoSchema>

/** Runtime validator for the temporary TOTP enrollment response. */
export const TOTPSetupDtoSchema = z.object({
  setup_token: z.string(),
  secret: z.string(),
  otpauth_uri: z.string(),
  /** Base64-encoded PNG bytes for the enrollment QR code, when present. */
  qr_png: z.string().optional(),
  /** One-time recovery codes; the server currently issues ten per enrollment. */
  recovery_codes: z.array(z.string()),
  /** Remaining lifetime of the enrollment, in seconds. */
  expires_in: z.number(),
})
/** Wire-format type inferred from {@link TOTPSetupDtoSchema}. */
export type TOTPSetupDto = z.infer<typeof TOTPSetupDtoSchema>

/** Runtime validator for VLESS profile delivery. */
const VLESSProfileDeliveryDtoSchema = z.object({
  client_id: z.string(), protocol: z.literal('vless'), uri: z.string(), json: z.json(),
})
/** Runtime validator for Hysteria 2 profile delivery. */
const HysteriaProfileDeliveryDtoSchema = z.object({
  client_id: z.string(), protocol: z.literal('hysteria2'), hysteria_uri: z.string(),
})
/** Runtime validator for VMess profile delivery. */
const VMessProfileDeliveryDtoSchema = z.object({
  client_id: z.string(), protocol: z.literal('vmess'), vmess_uri: z.string(), json: z.json(),
})
/** Runtime validator for migrated combined profiles; revoked protocols may be omitted. */
const LegacyProfileDeliveryDtoSchema = z.object({
  client_id: z.string(), protocol: z.literal('legacy_dual'), uri: z.string().optional(),
  hysteria_uri: z.string().optional(), json: z.json().optional(),
})
/** Runtime validator for a protocol-discriminated profile delivery response. */
export const ProfileDeliveryDtoSchema = z.discriminatedUnion('protocol', [
  VLESSProfileDeliveryDtoSchema, HysteriaProfileDeliveryDtoSchema, LegacyProfileDeliveryDtoSchema,
  VMessProfileDeliveryDtoSchema,
])
/** Wire-format type inferred from {@link ProfileDeliveryDtoSchema}. */
export type ProfileDeliveryDto = z.infer<typeof ProfileDeliveryDtoSchema>

/** Runtime validator for public metadata returned by Hysteria 2 certificate operations. */
export const HysteriaCertificateInfoDtoSchema = z.object({
  subject: z.string(),
  issuer: z.string(),
  dns_names: z.array(z.string()),
  ip_addresses: z.array(z.string()),
  not_before: z.string(),
  not_after: z.string(),
  fingerprint: z.string(),
})
/** Wire-format type inferred from {@link HysteriaCertificateInfoDtoSchema}. */
export type HysteriaCertificateInfoDto = z.infer<typeof HysteriaCertificateInfoDtoSchema>

/** Runtime validator for Hysteria 2 listener state; certificate keys are never included. */
export const HysteriaSettingsDtoSchema = z.object({
  enabled: z.boolean(),
  state: z.string(),
  host: z.string(),
  udp_port: z.number(),
  tls_mode: z.enum(['custom', 'self-signed', 'legacy']),
  tls_server_name: z.string(),
  tls_cert_ip: z.string().optional(),
  certificate_id: z.string().optional(),
  certificate: HysteriaCertificateInfoDtoSchema.optional(),
  certificate_error: z.string().optional(),
  runtime_error: z.string().optional(),
  udp_idle_timeout: z.number(),
  masquerade_type: z.enum(['off', 'string']),
  masquerade_string: z.string().optional(),
  insecure_uri: z.boolean(),
})
/** Wire-format type inferred from {@link HysteriaSettingsDtoSchema}. */
export type HysteriaSettingsDto = z.infer<typeof HysteriaSettingsDtoSchema>

/** Runtime validator for the preview returned before applying Hysteria 2 settings. */
export const HysteriaSettingsPreviewDtoSchema = z.discriminatedUnion('changed', [
  z.object({ changed: z.literal(false), settings: HysteriaSettingsDtoSchema }),
  z.object({
    changed: z.literal(true),
    change_id: z.string(),
    expires_in: z.number(),
    expected_confirmation: z.string(),
    requires_confirmation: z.boolean(),
    diff: z.array(z.object({ field: z.string(), from: z.string(), to: z.string() })),
    consequences: z.array(z.string()),
    settings: HysteriaSettingsDtoSchema,
  }),
])
/** Wire-format type inferred from {@link HysteriaSettingsPreviewDtoSchema}. */
export type HysteriaSettingsPreviewDto = z.infer<typeof HysteriaSettingsPreviewDtoSchema>

/** Runtime validator for the staged certificate version and its public metadata. */
export const HysteriaCertificateUploadDtoSchema = z.object({
  certificate_id: z.string(),
  certificate: HysteriaCertificateInfoDtoSchema,
})
/** Wire-format type inferred from {@link HysteriaCertificateUploadDtoSchema}. */
export type HysteriaCertificateUploadDto = z.infer<typeof HysteriaCertificateUploadDtoSchema>

/** Runtime validator for AmneziaWG service availability and listener metadata. */
export const AmneziaWGStatusDtoSchema = z.object({
  enabled: z.boolean(),
  available: z.boolean(),
  running: z.boolean(),
  public_key: z.string().optional(),
  listen_port: z.number().optional(),
  public_host: z.string().optional(),
  public_port: z.number().optional(),
  peer_count: z.number().optional(),
  ipv4_network: z.string().optional(),
  ipv6_network: z.string().optional(),
  service_version: z.string().optional(),
  error: z.string().optional(),
})
/** Wire-format type inferred from {@link AmneziaWGStatusDtoSchema}. */
export type AmneziaWGStatusDto = z.infer<typeof AmneziaWGStatusDtoSchema>

/** Runtime validator for a non-secret AmneziaWG peer summary. */
export const AmneziaWGPeerDtoSchema = z.object({
  name: z.string(),
  public_key: z.string(),
  ipv4: z.string(),
  ipv6: z.string(),
  created_at: z.string(),
})
/** Wire-format type inferred from {@link AmneziaWGPeerDtoSchema}. */
export type AmneziaWGPeerDto = z.infer<typeof AmneziaWGPeerDtoSchema>

/** Runtime validator for the AmneziaWG peer-list response. */
export const AmneziaWGPeersDtoSchema = z.object({ peers: AmneziaWGPeerDtoSchema.array() })
/** Wire-format type inferred from {@link AmneziaWGPeersDtoSchema}. */
export type AmneziaWGPeersDto = z.infer<typeof AmneziaWGPeersDtoSchema>

/** Runtime validator for the active server connection settings. */
export const SettingsDtoSchema = z.object({
  public_host: z.string(),
  public_port: z.number(),
  vmess_public_port: z.number(),
  reality_target: z.string(),
  reality_sni: z.string(),
  client_fingerprint: z.string(),
  log_level: z.enum(['debug', 'info', 'warning', 'error', 'none']),
  protocol: z.string(),
  network: z.string(),
  security: z.string(),
  flow: z.string(),
})
/** Wire-format type inferred from {@link SettingsDtoSchema}. */
export type SettingsDto = z.infer<typeof SettingsDtoSchema>

/** Runtime validator for a reviewed settings change and its consequences. */
export const SettingsChangeDtoSchema = z.object({
  change_id: z.string(),
  /** Remaining lifetime of this pending preview, in seconds. */
  expires_in: z.number(),
  /** Exact phrase required from the administrator when confirmation is needed. */
  expected_confirmation: z.string(),
  requires_confirmation: z.boolean(),
  diff: z.array(z.object({ field: z.string(), from: z.string(), to: z.string() })),
  consequences: z.array(z.string()),
  revoked_clients: z.number(),
  settings: SettingsDtoSchema,
})
/** Wire-format type inferred from {@link SettingsChangeDtoSchema}. */
export type SettingsChangeDto = z.infer<typeof SettingsChangeDtoSchema>

/** Runtime validator for Xray process health and recent errors. */
export const NodeStatusDtoSchema = z.object({
  state: z.string(),
  xray_version: z.string().optional(),
  configured_xray_version: z.string().optional(),
  xray_version_verified: z.boolean().optional(),
  restart_count: z.number(),
  last_error: z.string().optional(),
  last_exit: z.string().optional(),
  stats_last_error: z.string().optional(),
  supervisor_error: z.string().optional(),
})
/** Wire-format type inferred from {@link NodeStatusDtoSchema}. */
export type NodeStatusDto = z.infer<typeof NodeStatusDtoSchema>

/** Runtime validator for one masked diagnostic event. */
export const DiagnosticEntryDtoSchema = z.object({
  at: z.string(),
  component: z.string(),
  level: z.string(),
  message: z.string(),
})
/** Wire-format type inferred from {@link DiagnosticEntryDtoSchema}. */
export type DiagnosticEntryDto = z.infer<typeof DiagnosticEntryDtoSchema>

/** Runtime validator for the diagnostic log response envelope. */
export const DiagnosticEntriesDtoSchema = z.object({
  entries: z.array(DiagnosticEntryDtoSchema),
})
/** Wire-format type inferred from {@link DiagnosticEntriesDtoSchema}. */
export type DiagnosticEntriesDto = z.infer<typeof DiagnosticEntriesDtoSchema>

/** Runtime validator for a created backup's metadata. */
export const BackupDtoSchema = z.object({ name: z.string() })
/** Wire-format type inferred from {@link BackupDtoSchema}. */
export type BackupDto = z.infer<typeof BackupDtoSchema>

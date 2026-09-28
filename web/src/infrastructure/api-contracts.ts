import { z } from 'zod'

/** Runtime validator for the first-run status response in snake_case wire format. */
export const SetupStatusDtoSchema = z.object({
  initialized: z.boolean(),
  /** Configured public Xray listener port, when the server includes it. */
  public_port: z.number().optional(),
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

/** Runtime validator for a device and its traffic statistics. */
export const ClientDtoSchema = z.object({
  id: z.string(),
  name: z.string(),
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

/** Runtime validator for the downloadable URI and JSON device profile. */
export const ProfileDeliveryDtoSchema = z.object({
  client_id: z.string(),
  uri: z.string(),
  json: z.json(),
})
/** Wire-format type inferred from {@link ProfileDeliveryDtoSchema}. */
export type ProfileDeliveryDto = z.infer<typeof ProfileDeliveryDtoSchema>

/** Runtime validator for the active server connection settings. */
export const SettingsDtoSchema = z.object({
  public_host: z.string(),
  public_port: z.number(),
  reality_target: z.string(),
  reality_sni: z.string(),
  client_fingerprint: z.string(),
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

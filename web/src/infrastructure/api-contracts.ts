import { z } from 'zod'

export const SetupStatusDtoSchema = z.object({
  initialized: z.boolean(),
  public_port: z.number().optional(),
})
export type SetupStatusDto = z.infer<typeof SetupStatusDtoSchema>

export const AdminDtoSchema = z.object({
  username: z.string(),
  totp_enabled: z.boolean().optional(),
  recovery_codes_remaining: z.number().optional(),
})
export type AdminDto = z.infer<typeof AdminDtoSchema>

export const ClientDtoSchema = z.object({
  id: z.string(),
  name: z.string(),
  enabled: z.boolean(),
  revoked: z.boolean(),
  fingerprint: z.string().optional(),
  online: z.boolean(),
  last_seen: z.string().optional(),
  upload_bytes: z.number(),
  download_bytes: z.number(),
})
export type ClientDto = z.infer<typeof ClientDtoSchema>

export const TOTPStatusDtoSchema = z.object({
  enabled: z.boolean(),
  recovery_codes_remaining: z.number(),
})
export type TOTPStatusDto = z.infer<typeof TOTPStatusDtoSchema>

export const TOTPSetupDtoSchema = z.object({
  setup_token: z.string(),
  secret: z.string(),
  otpauth_uri: z.string(),
  qr_png: z.string().optional(),
  recovery_codes: z.array(z.string()),
  expires_in: z.number(),
})
export type TOTPSetupDto = z.infer<typeof TOTPSetupDtoSchema>

export const ProfileDeliveryDtoSchema = z.object({
  client_id: z.string(),
  uri: z.string(),
  json: z.json(),
})
export type ProfileDeliveryDto = z.infer<typeof ProfileDeliveryDtoSchema>

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
export type SettingsDto = z.infer<typeof SettingsDtoSchema>

export const SettingsChangeDtoSchema = z.object({
  change_id: z.string(),
  expires_in: z.number(),
  expected_confirmation: z.string(),
  requires_confirmation: z.boolean(),
  diff: z.array(z.object({ field: z.string(), from: z.string(), to: z.string() })),
  consequences: z.array(z.string()),
  revoked_clients: z.number(),
  settings: SettingsDtoSchema,
})
export type SettingsChangeDto = z.infer<typeof SettingsChangeDtoSchema>

export const NodeStatusDtoSchema = z.object({
  state: z.string(),
  restart_count: z.number(),
  last_error: z.string().optional(),
  last_exit: z.string().optional(),
  stats_last_error: z.string().optional(),
  supervisor_error: z.string().optional(),
})
export type NodeStatusDto = z.infer<typeof NodeStatusDtoSchema>

export const DiagnosticEntryDtoSchema = z.object({
  at: z.string(),
  component: z.string(),
  level: z.string(),
  message: z.string(),
})
export type DiagnosticEntryDto = z.infer<typeof DiagnosticEntryDtoSchema>

export const DiagnosticEntriesDtoSchema = z.object({
  entries: z.array(DiagnosticEntryDtoSchema),
})
export type DiagnosticEntriesDto = z.infer<typeof DiagnosticEntriesDtoSchema>

export const BackupDtoSchema = z.object({ name: z.string() })
export type BackupDto = z.infer<typeof BackupDtoSchema>

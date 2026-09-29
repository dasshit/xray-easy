import type {
  Admin,
  CreateAmneziaWGPeerCommand,
  CreateClientCommand,
  DiagnosticEntry,
  HysteriaCertificateUpload,
  HysteriaSettings,
  HysteriaSettingsCommand,
  HysteriaSettingsPreview,
  InitializeSetupCommand,
  NodeStatus,
  ProfileDelivery,
  SettingsPreviewCommand,
  SetupStatus,
  TOTPSetup,
  TOTPStatus,
} from '../models'
import type { AmneziaWGPeer, AmneziaWGStatus, Client, ClientActionType, Settings, SettingsChange } from '../../domain/models'

/** Callbacks invoked by the live server event stream. */
export interface XrayEventCallbacks {
  /** Called when device traffic statistics change. */
  onStats: () => void
  /** Called when Xray node status or diagnostics change. */
  onStatus: () => void
  /** Called when the event stream fails. */
  onError: () => void
}

/** Handle used to stop receiving live server events. */
export interface EventSubscription {
  /** Close the event subscription and stop receiving server updates. */
  close(): void
}

/** Application-facing operations implemented by the HTTP and SSE adapters. */
export interface XrayEasyGateway {
  setup: {
    /**
     * Read whether first-run setup has been completed.
     * @returns The initialization state, public port, and optional mkcert IPv4 suggestion.
     * @rejects {Error} When the setup status request fails.
     */
    status(): Promise<SetupStatus>
    /**
     * Save the initial administrator and server configuration.
     * @param input - The administrator credentials and initial Xray connection settings.
     * @rejects {Error} When validation or initial configuration fails.
     */
    initialize(input: InitializeSetupCommand): Promise<void>
  }
  auth: {
    /**
     * Read the administrator associated with the current session.
     * @returns The authenticated administrator and security status.
     * @rejects {Error} When the current session is missing or invalid.
     */
    current(): Promise<Admin>
    /**
     * Authenticate the administrator with a password.
     * @param username - The administrator login name.
     * @param password - The administrator password.
     * @returns The authenticated administrator.
     * @rejects {Error} When credentials are invalid or a second factor is required.
     */
    login(username: string, password: string): Promise<Admin>
    /**
     * Authenticate the administrator with a password and TOTP code.
     * @param username - The administrator login name.
     * @param password - The administrator password.
     * @param code - The current authenticator code.
     * @returns The authenticated administrator.
     * @rejects {Error} When credentials or the TOTP code are invalid.
     */
    loginWithTOTP(username: string, password: string, code: string): Promise<Admin>
    /**
     * Authenticate the administrator with a password and one-time recovery code.
     * @param username - The administrator login name.
     * @param password - The administrator password.
     * @param code - The unused recovery code.
     * @returns The authenticated administrator.
     * @rejects {Error} When credentials or the recovery code are invalid.
     */
    loginWithRecoveryCode(username: string, password: string, code: string): Promise<Admin>
    /**
     * End the current administrator session.
     * @rejects {Error} When the session cannot be ended.
     */
    logout(): Promise<void>
    /**
     * End all administrator sessions.
     * @rejects {Error} When sessions cannot be ended.
     */
    logoutAll(): Promise<void>
    /**
     * Change the administrator password and end every active session.
     * @param currentPassword - The current administrator password.
     * @param newPassword - The replacement password, at least twelve characters long.
     * @rejects {Error} When the current password is invalid or the replacement password is rejected.
     */
    changePassword(currentPassword: string, newPassword: string): Promise<void>
    /**
     * Read whether TOTP is enabled and how many recovery codes remain.
     * @returns The TOTP enrollment status.
     * @rejects {Error} When the TOTP status request fails.
     */
    totpStatus(): Promise<TOTPStatus>
    /**
     * Start TOTP enrollment and obtain the secret, QR data, and recovery codes.
     * @returns The temporary TOTP setup data.
     * @rejects {Error} When TOTP enrollment cannot be started.
     */
    beginTOTPSetup(): Promise<TOTPSetup>
    /**
     * Enable TOTP after verifying the enrollment code.
     * @param setupToken - The temporary token returned by beginTOTPSetup.
     * @param code - The authenticator code generated from the enrollment secret.
     * @rejects {Error} When the setup token or authenticator code is invalid.
     */
    enableTOTP(setupToken: string, code: string): Promise<void>
    /**
     * Disable TOTP after verifying the administrator credentials.
     * @param password - The current administrator password.
     * @param code - The current authenticator code.
     * @rejects {Error} When the password or authenticator code is invalid.
     */
    disableTOTP(password: string, code: string): Promise<void>
  }
  clients: {
    /**
     * List the administrator’s devices and their current statistics.
     * @returns The configured devices.
     * @rejects {Error} When the device list request fails.
     */
    list(): Promise<Client[]>
    /**
     * Create a device profile for a new client installation.
     * @param input - The device name, selected protocol, and optional protocol-specific credentials.
     * @returns The newly created single-protocol device.
     * @rejects {Error} When the input or server configuration is rejected.
     */
    create(input: CreateClientCommand): Promise<Client>
    /**
     * Read the connection profile for a device.
     * @param clientId - The internal ID of the device.
     * @returns A protocol-specific profile URI and any supported JSON configuration.
     * @rejects {Error} When the device is missing or its profile cannot be generated.
     */
    profile(clientId: string): Promise<ProfileDelivery>
    /**
     * Enable, disable, or revoke a device profile.
     * @param clientId - The internal ID of the device.
     * @param action - The action to apply.
     * @returns The updated device state.
     * @rejects {Error} When the action cannot be applied to the device.
     */
    setAction(clientId: string, action: ClientActionType): Promise<Client>
    /**
     * Build the authenticated URL for a device’s QR code.
     * @param clientId - The internal ID of the device.
     * @returns The API URL that serves the QR code image.
     */
    profileQrUrl(clientId: string): string
    /** Build the authenticated URL for a Hysteria 2 share URI QR code. */
    profileHysteriaQrUrl(clientId: string): string
    /** Build the authenticated URL for a VMess share URI QR code. */
    profileVMessQrUrl(clientId: string): string
    /**
     * Build the authenticated URL for a device’s JSON profile.
     * @param clientId - The internal ID of the device.
     * @returns The API URL that serves the JSON profile.
     */
    profileJsonUrl(clientId: string): string
  }
  settings: {
    /**
     * Read the active Xray connection settings.
     * @returns The current public endpoint and REALITY configuration.
     * @rejects {Error} When the settings request fails.
     */
    get(): Promise<Settings>
    /**
     * Preview settings changes and their effect on existing profiles and Xray runtime.
     * @param input - The proposed endpoint, REALITY target, fingerprint, log level, and key-rotation choice.
     * @returns The proposed settings, diff, consequences, and confirmation details.
     * @rejects {Error} When the proposed settings are invalid.
     */
    preview(input: SettingsPreviewCommand): Promise<Omit<SettingsChange, 'confirmation'>>
    /**
     * Apply a reviewed settings change after explicit confirmation.
     * @param changeId - The ID returned by the settings preview.
     * @param confirmation - The exact confirmation phrase required by the preview.
     * @rejects {Error} When the preview expired or confirmation does not match.
     */
    apply(changeId: string, confirmation: string): Promise<void>
  }
  hysteria: {
    /**
     * Read the authenticated Hysteria 2 inbound status and certificate metadata.
     * @returns The current Hysteria 2 settings without private key data.
     * @rejects {Error} When the status request fails.
     */
    status(): Promise<HysteriaSettings>
    /**
     * Stage a trusted PEM certificate and matching private key for review.
     * @param fullchain - The PEM certificate chain file.
     * @param privateKey - The matching PEM private key file.
     * @param serverName - The host name or IP address the certificate must cover.
     * @returns The new immutable certificate version and its public metadata.
     * @rejects {Error} When the upload is too large, untrusted, expired, or mismatched.
     */
    uploadCertificate(fullchain: File, privateKey: File, serverName: string): Promise<HysteriaCertificateUpload>
    /**
     * Generate a temporary-CA mkcert certificate for one public IPv4 address.
     * @param ipv4 - The public IPv4 address to include in the certificate.
     * @returns The staged certificate version and its public metadata.
     * @rejects {Error} When mkcert is unavailable or the address is invalid.
     */
    generateCertificate(ipv4: string): Promise<HysteriaCertificateUpload>
    /**
     * Preview Hysteria 2 settings and show effects before applying them.
     * @param input - The proposed inbound, TLS, timeout, and masquerade settings.
     * @returns The change preview, or the current settings if nothing changed.
     * @rejects {Error} When settings or the selected certificate are invalid.
     */
    preview(input: HysteriaSettingsCommand): Promise<HysteriaSettingsPreview>
    /**
     * Apply the reviewed Hysteria 2 inbound change through Xray HandlerService.
     * @param changeId - The change identifier returned by preview.
     * @param confirmation - The exact confirmation phrase shown in the preview.
     * @rejects {Error} When the preview expires, confirmation fails, or Xray rejects the inbound.
     */
    apply(changeId: string, confirmation: string): Promise<void>
  }
  amneziawg: {
    /** Read the optional service's availability and public endpoint. */
    status(): Promise<AmneziaWGStatus>
    /** List non-secret metadata for all configured AmneziaWG peers. */
    listPeers(): Promise<AmneziaWGPeer[]>
    /** Create a peer and persist its private client profile inside the AWG service. */
    createPeer(input: CreateAmneziaWGPeerCommand): Promise<AmneziaWGPeer>
    /** Revoke a peer and remove its saved client profile. */
    removePeer(name: string): Promise<void>
    /** Build the authenticated URL that downloads a peer's credential-bearing profile. */
    profileUrl(name: string): string
    /** Build the authenticated URL that renders a credential-bearing profile QR code. */
    profileQrUrl(name: string): string
  }
  backups: {
    /**
     * Create a backup of the current application data.
     * @returns The backup filename.
     * @rejects {Error} When the backup cannot be created.
     */
    create(): Promise<{ name: string }>
  }
  diagnostics: {
    /**
     * Read the supervised Xray node status.
     * @returns The node state, restart count, and last known errors.
     * @rejects {Error} When the status request fails.
     */
    status(): Promise<NodeStatus>
    /**
     * Read recent masked log entries for one component.
     * @param component - The component whose logs should be returned.
     * @param limit - The maximum number of entries to request.
     * @returns Recent diagnostic entries for the component.
     * @rejects {Error} When the log request fails.
     */
    logs(component: string, limit?: number): Promise<DiagnosticEntry[]>
  }
  events: {
    /**
     * Subscribe to live status and statistics updates.
     * @param callbacks - The handlers invoked for statistics, status, and stream errors.
     * @returns A subscription that can close the event stream.
     * @throws {Error} When the event source cannot be created.
     */
    connect(callbacks: XrayEventCallbacks): EventSubscription
  }
}

import type { XrayEasyGateway } from '../ports/xrayEasyGateway'
import type { DiagnosticEntry, NodeStatus, TOTPStatus } from '../models'
import type { Client, Settings } from '../../domain/models'

export type AuthenticatedDashboard = {
  clients: Client[]
  totpStatus: TOTPStatus
  settings: Settings
  nodeStatus: NodeStatus
  diagnostics: DiagnosticEntry[]
}

/**
 * Read node status and return an unavailable state if the request fails.
 * @param api - The application gateway used to read node status.
 * @returns The current node status or an unavailable fallback.
 */
async function loadNodeStatus(api: XrayEasyGateway): Promise<NodeStatus> {
  try {
    return await api.diagnostics.status()
  } catch {
    return { state: 'unavailable' }
  }
}

/**
 * Load, merge, sort, and limit the recent logs from Xray and the control plane.
 * @param api - The application gateway used to read logs.
 * @returns At most the latest 100 diagnostic entries.
 */
async function loadDiagnostics(api: XrayEasyGateway): Promise<DiagnosticEntry[]> {
  const results = await Promise.allSettled([api.diagnostics.logs('xray', 100), api.diagnostics.logs('app', 100)])
  return results
    .flatMap(result => result.status === 'fulfilled' ? result.value : [])
    .sort((left, right) => left.at.localeCompare(right.at))
    .slice(-100)
}

/**
 * Load the datasets required to render the authenticated dashboard.
 * @param api - The application gateway used to read dashboard data.
 * @returns The device, security, settings, status, and diagnostic data.
 * @rejects {Error} When a required dashboard request fails.
 */
export async function loadAuthenticatedDashboard(api: XrayEasyGateway): Promise<AuthenticatedDashboard> {
  const [clients, totpStatus, settings, nodeStatus, diagnostics] = await Promise.all([
    api.clients.list(),
    api.auth.totpStatus(),
    api.settings.get(),
    loadNodeStatus(api),
    loadDiagnostics(api),
  ])
  return { clients, totpStatus, settings, nodeStatus, diagnostics }
}

/**
 * Load the latest diagnostic entries for a dashboard refresh.
 * @param api - The application gateway used to read logs.
 * @returns The latest diagnostic entries.
 */
export async function loadDiagnosticsSnapshot(api: XrayEasyGateway): Promise<DiagnosticEntry[]> {
  return loadDiagnostics(api)
}

/**
 * Load node status for a dashboard refresh.
 * @param api - The application gateway used to read node status.
 * @returns The current node status or an unavailable fallback.
 */
export async function loadNodeStatusSnapshot(api: XrayEasyGateway): Promise<NodeStatus> {
  return loadNodeStatus(api)
}

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

async function loadNodeStatus(api: XrayEasyGateway): Promise<NodeStatus> {
  try {
    return await api.diagnostics.status()
  } catch {
    return { state: 'unavailable', restartCount: 0 }
  }
}

async function loadDiagnostics(api: XrayEasyGateway): Promise<DiagnosticEntry[]> {
  const results = await Promise.allSettled([api.diagnostics.logs('xray', 100), api.diagnostics.logs('app', 100)])
  return results
    .flatMap(result => result.status === 'fulfilled' ? result.value : [])
    .sort((left, right) => left.at.localeCompare(right.at))
    .slice(-100)
}

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

export async function loadDiagnosticsSnapshot(api: XrayEasyGateway): Promise<DiagnosticEntry[]> {
  return loadDiagnostics(api)
}

export async function loadNodeStatusSnapshot(api: XrayEasyGateway): Promise<NodeStatus> {
  return loadNodeStatus(api)
}

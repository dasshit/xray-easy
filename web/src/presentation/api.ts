import type { InjectionKey } from 'vue'
import type { XrayEasyGateway } from '../application/ports/xrayEasyGateway'

export const xrayEasyGatewayKey: InjectionKey<XrayEasyGateway> = Symbol('xrayEasyGateway')

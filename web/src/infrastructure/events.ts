import type { EventSubscription, XrayEventCallbacks } from '../application/ports/xrayEasyGateway'

type EventSourceLike = Pick<EventSource, 'addEventListener' | 'close'> & Pick<EventSource, 'onerror'>
export type EventSourceFactory = (url: string) => EventSourceLike

export function connectXrayEvents(
  callbacks: XrayEventCallbacks,
  createSource: EventSourceFactory = url => new EventSource(url),
): EventSubscription {
  const source = createSource('/api/events')
  source.addEventListener('stats', callbacks.onStats)
  source.addEventListener('status', callbacks.onStatus)
  source.onerror = callbacks.onError
  return { close: () => source.close() }
}

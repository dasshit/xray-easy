import type { EventSubscription, XrayEventCallbacks } from '../application/ports/xrayEasyGateway'

type EventSourceLike = Pick<EventSource, 'addEventListener' | 'close'> & Pick<EventSource, 'onerror'>
export type EventSourceFactory = (url: string) => EventSourceLike

/**
 * Subscribe to Xray status and statistics events through server-sent events.
 *
 * @param callbacks - Handlers for statistics, status, and stream errors.
 * @param createSource - Event source factory; defaults to the browser EventSource.
 * @returns A subscription that closes the event source.
 */
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

// @vitest-environment node

import { describe, expect, it, vi } from 'vitest'
import { connectXrayEvents, type EventSourceFactory } from './events'

function fakeSource() {
  const listeners = new Map<string, EventListener>()
  const source = {
    addEventListener: vi.fn((type: string, listener: EventListener) => listeners.set(type, listener)),
    close: vi.fn(),
    onerror: null as ((this: EventSource, event: Event) => unknown) | null,
  }
  return { source, listeners }
}

describe('Xray event stream adapter', () => {
  it('binds typed event callbacks and closes the underlying source', () => {
    const fake = fakeSource()
    const createSource = vi.fn(() => fake.source) as unknown as EventSourceFactory
    const onStats = vi.fn()
    const onStatus = vi.fn()
    const onError = vi.fn()
    const subscription = connectXrayEvents({ onStats, onStatus, onError }, createSource)

    expect(createSource).toHaveBeenCalledWith('/api/events')
    fake.listeners.get('stats')?.(new Event('stats'))
    fake.listeners.get('status')?.(new Event('status'))
    fake.source.onerror?.call(fake.source as unknown as EventSource, new Event('error'))
    expect(onStats).toHaveBeenCalledOnce()
    expect(onStatus).toHaveBeenCalledOnce()
    expect(onError).toHaveBeenCalledOnce()

    subscription.close()
    expect(fake.source.close).toHaveBeenCalledOnce()
  })
})

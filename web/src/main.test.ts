import { beforeEach, describe, expect, it, vi } from 'vitest'

const { appMount } = vi.hoisted(() => ({ appMount: vi.fn() }))

vi.mock('vue', () => ({
  createApp: vi.fn(() => ({ mount: appMount })),
}))
vi.mock('./App.vue', () => ({ default: { name: 'AppStub' } }))

describe('web entrypoint', () => {
  beforeEach(() => {
    appMount.mockClear()
  })

  it('mounts the root app in the application element', async () => {
    await import('./main')
    expect(appMount).toHaveBeenCalledWith('#app')
  })
})

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { xrayEasyGatewayKey } from './presentation/api'

const { appMount, appProvide } = vi.hoisted(() => ({ appMount: vi.fn(), appProvide: vi.fn() }))

vi.mock('vue', () => ({
  createApp: vi.fn(() => {
    const app = { provide: appProvide, mount: appMount }
    appProvide.mockReturnValue(app)
    return app
  }),
}))
vi.mock('./App.vue', () => ({ default: { name: 'AppStub' } }))

describe('web entrypoint', () => {
  beforeEach(() => {
    appMount.mockClear()
    appProvide.mockClear()
  })

  it('provides the concrete API adapter and mounts the root app in the application element', async () => {
    await import('./main')
    expect(appProvide).toHaveBeenCalledWith(xrayEasyGatewayKey, expect.objectContaining({ clients: expect.any(Object) }))
    expect(appMount).toHaveBeenCalledWith('#app')
  })
})

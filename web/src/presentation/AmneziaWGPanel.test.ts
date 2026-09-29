import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import type { XrayEasyGateway } from '../application/ports/xrayEasyGateway'
import type { AmneziaWGPeer } from '../domain/models'
import { translations } from './i18n/messages'
import AmneziaWGPanel from './AmneziaWGPanel.vue'

const peer: AmneziaWGPeer = {
  name: 'iphone', publicKey: 'server-public-key', ipv4: '10.88.0.2', ipv6: 'fd88:88:88::2', createdAt: '2026-09-30T12:00:00Z',
}

function gateway(overrides: Partial<XrayEasyGateway['amneziawg']> = {}): XrayEasyGateway {
  const amneziawg: XrayEasyGateway['amneziawg'] = {
    status: vi.fn().mockResolvedValue({ enabled: true, available: true, running: true, publicHost: 'vpn.example.test', publicPort: 51820, listenPort: 51820, peerCount: 1, ipv4Network: '10.88.0.0/24', ipv6Network: 'fd88:88:88::/64' }),
    listPeers: vi.fn().mockResolvedValue([peer]),
    createPeer: vi.fn().mockResolvedValue(peer),
    removePeer: vi.fn().mockResolvedValue(undefined),
    profileUrl: vi.fn().mockReturnValue('/profile.conf'),
    profileQrUrl: vi.fn().mockReturnValue('/profile.png'),
  }
  return { amneziawg: { ...amneziawg, ...overrides } } as unknown as XrayEasyGateway
}

describe('AmneziaWGPanel', () => {
  it('shows setup guidance while the optional service is not available', async () => {
    const api = gateway({ status: vi.fn().mockResolvedValue({ enabled: false, available: false, running: false }) })
    const wrapper = mount(AmneziaWGPanel, { props: { api, language: 'en' } })
    await flushPromises()
    expect(wrapper.text()).toContain('./install.sh')
    expect(api.amneziawg.listPeers).not.toHaveBeenCalled()
  })

  it('creates a peer and offers its private profile as QR and download', async () => {
    const api = gateway({
      createPeer: vi.fn().mockResolvedValue(peer),
      listPeers: vi.fn().mockResolvedValueOnce([]).mockResolvedValueOnce([peer]),
    })
    const wrapper = mount(AmneziaWGPanel, { props: { api, language: 'en' } })
    await flushPromises()
    await wrapper.get('input').setValue('iphone')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(api.amneziawg.createPeer).toHaveBeenCalledWith({ name: 'iphone' })
    expect(wrapper.get('[role="dialog"] img').attributes('src')).toBe('/profile.png')
    expect(wrapper.get('[role="dialog"] a').attributes('href')).toBe('/profile.conf')
    expect(wrapper.text()).toContain('The QR code and file contain the device private key.')
  })

  it('requires explicit confirmation before revoking a peer', async () => {
    const api = gateway()
    const wrapper = mount(AmneziaWGPanel, { props: { api, language: 'ru' } })
    await flushPromises()
    expect(wrapper.find('.online').exists()).toBe(false)
    await wrapper.get('.device-actions .danger').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain(translations.ru.awgConfirmRevoke)
    expect(api.amneziawg.removePeer).not.toHaveBeenCalled()
    const dialog = wrapper.get('[role="dialog"]')
    await dialog.findAll('button').at(-1)?.trigger('click')
    await flushPromises()
    expect(api.amneziawg.removePeer).toHaveBeenCalledWith('iphone')
  })
})

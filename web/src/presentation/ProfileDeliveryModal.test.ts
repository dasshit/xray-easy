import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import type { Client } from '../domain/models'
import ProfileDeliveryModal from './ProfileDeliveryModal.vue'

const client: Client = {
  id: 'client-1', name: 'phone', protocol: 'hysteria2', protocols: ['hysteria2'],
  hysteria2: { enabled: true, revoked: false }, enabled: true, revoked: false,
  online: false, uploadBytes: 0, downloadBytes: 0,
}

describe('ProfileDeliveryModal', () => {
  it('shows only the Hysteria 2 URI and QR for a Hysteria profile', async () => {
    const wrapper = mount(ProfileDeliveryModal, { props: {
      profile: { clientId: client.id, protocol: 'hysteria2', hysteriaUri: 'hysteria2://secret@vpn.test:443' },
      client, language: 'en', vlessQrUrl: '/vless-qr', hysteriaQrUrl: '/hysteria-qr', jsonUrl: '/json', copiedVless: false, copiedHysteria: false,
    } })

    expect((wrapper.get('textarea').element as HTMLTextAreaElement).value).toBe('hysteria2://secret@vpn.test:443')
    expect(wrapper.find('img').attributes('src')).toBe('/hysteria-qr')
    expect(wrapper.text()).not.toContain('VLESS URI')
    expect(wrapper.text()).not.toContain('JSON file')
    expect(wrapper.text()).toContain('Hysteria 2 profile')
    await wrapper.findAll('button').find(button => button.text().includes('Copy Hysteria 2 link'))?.trigger('click')
    expect(wrapper.emitted('copyHysteria')).toHaveLength(1)
  })

  it('retains both delivery sections for legacy combined profiles', () => {
    const wrapper = mount(ProfileDeliveryModal, { props: {
      profile: { clientId: client.id, protocol: 'legacy_dual', uri: 'vless://id', hysteriaUri: 'hysteria2://auth@vpn.test:443', json: { outbound: true } },
      client: { ...client, protocol: 'legacy_dual', protocols: ['vless', 'hysteria2'], vless: { enabled: true, revoked: false } },
      language: 'ru', vlessQrUrl: '/vless-qr', hysteriaQrUrl: '/hysteria-qr', jsonUrl: '/json', copiedVless: false, copiedHysteria: false,
    } })

    expect(wrapper.text()).toContain('Старый профиль · VLESS + Hysteria 2')
    expect((wrapper.get('textarea').element as HTMLTextAreaElement).value).toBe('vless://id')
    expect((wrapper.findAll('textarea')[1]?.element as HTMLTextAreaElement).value).toBe('hysteria2://auth@vpn.test:443')
    expect(wrapper.findAll('img')).toHaveLength(2)
    expect(wrapper.text()).toContain('JSON-файл')
  })
})

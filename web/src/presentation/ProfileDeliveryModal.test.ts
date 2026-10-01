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
      client, language: 'en', vlessQrUrl: '/vless-qr', hysteriaQrUrl: '/hysteria-qr', vmessQrUrl: '/vmess-qr', jsonUrl: '/json', copiedVless: false, copiedHysteria: false, copiedVmess: false,
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
      language: 'ru', vlessQrUrl: '/vless-qr', hysteriaQrUrl: '/hysteria-qr', vmessQrUrl: '/vmess-qr', jsonUrl: '/json', copiedVless: false, copiedHysteria: false, copiedVmess: false,
    } })

    expect(wrapper.text()).toContain('Старый профиль · VLESS + Hysteria 2')
    expect((wrapper.get('textarea').element as HTMLTextAreaElement).value).toBe('vless://id')
    expect((wrapper.findAll('textarea')[1]?.element as HTMLTextAreaElement).value).toBe('hysteria2://auth@vpn.test:443')
    expect(wrapper.findAll('img')).toHaveLength(2)
    expect(wrapper.text()).toContain('JSON-файл')
  })

  it('shows only VMess share link, QR, and JSON export', async () => {
    const wrapper = mount(ProfileDeliveryModal, { props: {
      profile: { clientId: client.id, protocol: 'vmess', vmessUri: 'vmess://base64-profile', json: { outbound: true } },
      client: { ...client, protocol: 'vmess', protocols: ['vmess'], vmess: { enabled: true, revoked: false } },
      language: 'en', vlessQrUrl: '/vless-qr', hysteriaQrUrl: '/hysteria-qr', vmessQrUrl: '/vmess-qr', jsonUrl: '/json', copiedVless: false, copiedHysteria: false, copiedVmess: false,
    } })

    expect(wrapper.text()).toContain('VMess + TLS profile')
    expect((wrapper.get('textarea').element as HTMLTextAreaElement).value).toBe('vmess://base64-profile')
    expect(wrapper.find('img').attributes('src')).toBe('/vmess-qr')
    expect(wrapper.find('a').attributes('href')).toBe('/json')
    expect(wrapper.text()).not.toContain('VLESS URI')
    expect(wrapper.text()).not.toContain('Hysteria 2 URI')
    await wrapper.findAll('button').find(button => button.text().includes('Copy VMess link'))?.trigger('click')
    expect(wrapper.emitted('copyVmess')).toHaveLength(1)
  })

  it('shows the Shadowsocks URI, QR, and JSON export', async () => {
    const wrapper = mount(ProfileDeliveryModal, { props: {
      profile: { clientId: client.id, protocol: 'shadowsocks', ssUri: 'ss://encoded#tablet', json: { server: 'vpn.test' } },
      client: { ...client, protocol: 'shadowsocks', protocols: ['shadowsocks'], shadowsocks: { enabled: true, revoked: false } },
      language: 'en', vlessQrUrl: '/vless-qr', hysteriaQrUrl: '/hysteria-qr', vmessQrUrl: '/vmess-qr', shadowsocksQrUrl: '/ss-qr', jsonUrl: '/json', copiedVless: false, copiedHysteria: false, copiedVmess: false, copiedShadowsocks: false,
    } })

    expect(wrapper.text()).toContain('Shadowsocks profile')
    expect((wrapper.get('textarea').element as HTMLTextAreaElement).value).toBe('ss://encoded#tablet')
    expect(wrapper.find('img').attributes('src')).toBe('/ss-qr')
    expect(wrapper.find('a.download-link').attributes('href')).toBe('/json')
    await wrapper.findAll('button').find(button => button.text().includes('Copy Shadowsocks link'))?.trigger('click')
    expect(wrapper.emitted('copyShadowsocks')).toHaveLength(1)
  })

  it('shows AmneziaWG QR and downloads its private profile from the AWG service', () => {
    const wrapper = mount(ProfileDeliveryModal, { props: {
      profile: { clientId: 'awg:iphone', protocol: 'amneziawg', name: 'iphone' },
      client: { ...client, id: 'awg:iphone', protocol: 'amneziawg', protocols: ['amneziawg'] },
      language: 'en', vlessQrUrl: '/vless-qr', hysteriaQrUrl: '/hysteria-qr', vmessQrUrl: '/vmess-qr',
      awgQrUrl: '/awg-qr', awgProfileUrl: '/awg-profile.conf', jsonUrl: '/json', copiedVless: false, copiedHysteria: false, copiedVmess: false,
    } })

    expect(wrapper.text()).toContain('The QR code and file contain the device private key')
    expect(wrapper.find('img').attributes('src')).toBe('/awg-qr')
    expect(wrapper.get('a.download-link').attributes('href')).toBe('/awg-profile.conf')
    expect(wrapper.text()).not.toContain('JSON file')
  })
})

import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import CreateProfileModal from './CreateProfileModal.vue'

describe('CreateProfileModal', () => {
  it('submits a VLESS-only profile with its optional fingerprint', async () => {
    const wrapper = mount(CreateProfileModal, { props: { language: 'en', hysteriaAvailable: true, vmessAvailable: true, busy: false } })
    await flushPromises()
    await wrapper.get('input[autocomplete="off"]').setValue('macbook')
    await wrapper.get('[data-testid="profile-protocol"]').setValue('vless')
    await wrapper.get('form').trigger('submit')

    expect(wrapper.emitted('submit')?.[0]?.[0]).toEqual({ name: 'macbook', protocol: 'vless' })
    expect(wrapper.find('details').exists()).toBe(false)
    expect(wrapper.text()).toContain('Creates a VLESS + REALITY profile')
  })

  it('keeps Hysteria unavailable until it is enabled with a certificate and links to settings', async () => {
    const wrapper = mount(CreateProfileModal, { props: { language: 'en', hysteriaAvailable: false, vmessAvailable: false, busy: false } })
    const option = wrapper.get('[data-testid="profile-protocol"] option[value="hysteria2"]')
    const vmessOption = wrapper.get('[data-testid="profile-protocol"] option[value="vmess"]')

    expect((option.element as HTMLOptionElement).disabled).toBe(true)
    expect((vmessOption.element as HTMLOptionElement).disabled).toBe(true)
    expect(wrapper.text()).toContain('Hysteria 2 needs to be enabled with a valid TLS certificate.')
    await wrapper.findAll('button').find(button => button.text() === 'Open Hysteria 2 settings')?.trigger('click')
    expect(wrapper.emitted('openSettings')).toHaveLength(1)
    await wrapper.get('input[autocomplete="off"]').setValue('phone')
    await wrapper.get('form').trigger('submit')
    expect(wrapper.emitted('submit')?.[0]?.[0]).toEqual({ name: 'phone', protocol: 'vless' })
  })

  it('shows only Hysteria fields, allows a custom password, and localizes them in Russian', async () => {
    const wrapper = mount(CreateProfileModal, { props: { language: 'ru', hysteriaAvailable: true, vmessAvailable: true, busy: false } })
    await wrapper.get('input[autocomplete="off"]').setValue('iphone')
    await wrapper.get('[data-testid="profile-protocol"]').setValue('hysteria2')
    expect(wrapper.text()).toContain('Создаст только профиль Hysteria 2')
    await wrapper.get('summary').trigger('click')
    await wrapper.get('input[autocomplete="new-password"]').setValue('custom-secret')
    await wrapper.get('form').trigger('submit')

    expect(wrapper.emitted('submit')?.[0]?.[0]).toEqual({ name: 'iphone', protocol: 'hysteria2', auth: 'custom-secret' })
    expect(wrapper.find('select option[value="safari"]').exists()).toBe(false)
    expect(wrapper.text()).toContain('Пароль Hysteria 2')
  })

  it('creates VMess only when a valid shared TLS certificate is available', async () => {
    const wrapper = mount(CreateProfileModal, { props: { language: 'en', hysteriaAvailable: false, vmessAvailable: true, busy: false } })
    await wrapper.get('input[autocomplete="off"]').setValue('macbook')
    await wrapper.get('[data-testid="profile-protocol"]').setValue('vmess')
    expect(wrapper.text()).toContain('server and client clocks must stay within two minutes')
    await wrapper.get('form').trigger('submit')

    expect(wrapper.emitted('submit')?.[0]?.[0]).toEqual({ name: 'macbook', protocol: 'vmess' })
    expect(wrapper.text()).not.toContain('Hysteria 2 needs to be enabled')
  })

  it('creates a Shadowsocks profile when the listener is enabled', async () => {
    const wrapper = mount(CreateProfileModal, { props: { language: 'en', hysteriaAvailable: false, vmessAvailable: false, shadowsocksAvailable: true, busy: false } })
    await wrapper.get('input[autocomplete="off"]').setValue('tablet')
    await wrapper.get('[data-testid="profile-protocol"]').setValue('shadowsocks')

    expect(wrapper.text()).toContain('Creates a Shadowsocks 2022 profile')
    await wrapper.get('form').trigger('submit')

    expect(wrapper.emitted('submit')?.[0]?.[0]).toEqual({ name: 'tablet', protocol: 'shadowsocks' })
  })

  it('selects AmneziaWG when the optional service is available', async () => {
    const wrapper = mount(CreateProfileModal, { props: { language: 'en', hysteriaAvailable: false, vmessAvailable: false, awgAvailable: true, busy: false } })
    await wrapper.get('input[autocomplete="off"]').setValue('iphone')
    await wrapper.get('[data-testid="profile-protocol"]').setValue('amneziawg')
    expect(wrapper.text()).toContain('Creates an AmneziaWG profile')
    await wrapper.get('form').trigger('submit')

    expect(wrapper.emitted('submit')?.[0]?.[0]).toEqual({ name: 'iphone', protocol: 'amneziawg' })
  })

  it('passes the selected expiry to the new profile request', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-10-01T12:00:00Z'))
    try {
      const wrapper = mount(CreateProfileModal, { props: { language: 'en', hysteriaAvailable: true, vmessAvailable: true, busy: false } })
      await wrapper.get('input[autocomplete="off"]').setValue('macbook')
      await wrapper.get('[data-testid="expiry-preset"]').setValue('7-days')
      await wrapper.get('form').trigger('submit')

      expect(wrapper.emitted('submit')?.[0]?.[0]).toEqual({ name: 'macbook', protocol: 'vless', expiresAt: '2026-10-08T12:00:00.000Z' })
    } finally {
      vi.useRealTimers()
    }
  })
})

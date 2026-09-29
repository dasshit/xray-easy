import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import CreateProfileModal from './CreateProfileModal.vue'

describe('CreateProfileModal', () => {
  it('submits a VLESS-only profile with its optional fingerprint', async () => {
    const wrapper = mount(CreateProfileModal, { props: { language: 'en', hysteriaAvailable: true, busy: false } })
    await flushPromises()
    await wrapper.get('input[autocomplete="off"]').setValue('macbook')
    await wrapper.get('[data-testid="profile-protocol"]').setValue('vless')
    await wrapper.get('form').trigger('submit')

    expect(wrapper.emitted('submit')?.[0]?.[0]).toEqual({ name: 'macbook', protocol: 'vless' })
    expect(wrapper.find('details').exists()).toBe(false)
    expect(wrapper.text()).toContain('Creates a VLESS + REALITY profile')
  })

  it('keeps Hysteria unavailable until it is enabled with a certificate and links to settings', async () => {
    const wrapper = mount(CreateProfileModal, { props: { language: 'en', hysteriaAvailable: false, busy: false } })
    const option = wrapper.get('[data-testid="profile-protocol"] option[value="hysteria2"]')

    expect((option.element as HTMLOptionElement).disabled).toBe(true)
    expect(wrapper.text()).toContain('Hysteria 2 needs to be enabled with a valid TLS certificate.')
    await wrapper.findAll('button').find(button => button.text() === 'Open Hysteria 2 settings')?.trigger('click')
    expect(wrapper.emitted('openSettings')).toHaveLength(1)
    await wrapper.get('input[autocomplete="off"]').setValue('phone')
    await wrapper.get('form').trigger('submit')
    expect(wrapper.emitted('submit')?.[0]?.[0]).toEqual({ name: 'phone', protocol: 'vless' })
  })

  it('shows only Hysteria fields, allows a custom password, and localizes them in Russian', async () => {
    const wrapper = mount(CreateProfileModal, { props: { language: 'ru', hysteriaAvailable: true, busy: false } })
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
})

import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import type { Client } from '../domain/models'
import ProfileExpiryModal from './ProfileExpiryModal.vue'

const client: Client = {
  id: 'profile-1', name: 'iphone', protocol: 'vless', protocols: ['vless'], enabled: false, revoked: false,
  expired: true, expirationPending: false, expiresAt: '2026-09-30T12:00:00Z', online: false, uploadBytes: 0, downloadBytes: 0,
}

describe('ProfileExpiryModal', () => {
  it('closes from the close button and cancel action, and disables actions while saving', async () => {
    const wrapper = mount(ProfileExpiryModal, { props: { client: { ...client, expired: false }, language: 'en', busy: false } })
    await wrapper.get('.icon-button').trigger('click')
    await wrapper.get('.modal-actions .secondary').trigger('click')
    expect(wrapper.emitted('close')).toHaveLength(2)

    await wrapper.setProps({ busy: true })
    expect((wrapper.get('.modal-actions .secondary').element as HTMLButtonElement).disabled).toBe(true)
    expect((wrapper.get('button[type="submit"]').element as HTMLButtonElement).disabled).toBe(true)
  })

  it('requires a future date for an expired profile and saves it without enabling access', async () => {
    const wrapper = mount(ProfileExpiryModal, { props: { client, language: 'en', busy: false } })
    await flushPromises()
    expect((wrapper.get('button[type="submit"]').element as HTMLButtonElement).disabled).toBe(true)
    await wrapper.get('[data-testid="expiry-custom"]').setValue('2099-02-03T12:00')
    expect((wrapper.get('button[type="submit"]').element as HTMLButtonElement).disabled).toBe(false)
    await wrapper.get('form').trigger('submit')

    expect(wrapper.emitted('save')?.[0]?.[0]).toBe(new Date('2099-02-03T12:00').toISOString())
    expect(wrapper.emitted('close')).toBeUndefined()
  })
})

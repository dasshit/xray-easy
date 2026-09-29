import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import type { HysteriaCertificateInfo, HysteriaSettings } from '../application/models'
import type { XrayEasyGateway } from '../application/ports/xrayEasyGateway'
import HysteriaSettingsPanel from './HysteriaSettingsPanel.vue'

const certificate: HysteriaCertificateInfo = {
  subject: 'CN=vpn.example.test', issuer: 'CN=Example CA', dnsNames: ['vpn.example.test'], ipAddresses: [],
  notBefore: '2026-09-01T00:00:00Z', notAfter: '2027-09-01T00:00:00Z', fingerprint: 'AABBCC',
}

const baseStatus: HysteriaSettings = {
  enabled: false, state: 'ready', host: 'vpn.example.test', udpPort: 443, tlsMode: 'custom', tlsServerName: 'vpn.example.test',
  certificateId: '0123456789abcdef0123456789abcdef', certificate, udpIdleTimeout: 60,
  masqueradeType: 'off', insecureUri: false,
}

function makeApi(status = baseStatus) {
  return {
    hysteria: {
      status: vi.fn().mockResolvedValue(status),
      uploadCertificate: vi.fn().mockResolvedValue({ certificateId: 'fedcba9876543210fedcba9876543210', certificate }),
      generateCertificate: vi.fn().mockResolvedValue({ certificateId: 'fedcba9876543210fedcba9876543210', certificate }),
      preview: vi.fn().mockResolvedValue({ changed: false as const, settings: status }),
      apply: vi.fn().mockResolvedValue(undefined),
    },
  } as unknown as XrayEasyGateway
}

describe('HysteriaSettingsPanel', () => {
  it('loads current settings and stages a mkcert certificate for IPv4', async () => {
    const api = makeApi()
    const wrapper = mount(HysteriaSettingsPanel, { props: { api, language: 'en' } })
    await flushPromises()
    expect(wrapper.text()).toContain('Ready to enable')
    expect(wrapper.text()).toContain('443/UDP')

    await wrapper.get('select').setValue('self-signed')
    await wrapper.get('input[inputmode="decimal"]').setValue('89.169.13.234')
    expect((wrapper.get('input[readonly]').element as HTMLInputElement).value).toBe('89.169.13.234')
    await wrapper.get('button').trigger('click')
    await flushPromises()
    expect(api.hysteria.generateCertificate).toHaveBeenCalledWith('89.169.13.234')
    expect(wrapper.text()).toContain('Certificate staged')
    expect(wrapper.text()).toContain('insecure=1')
  })

  it('uploads a trusted certificate and applies a confirmed inbound update', async () => {
    const api = makeApi()
    api.hysteria.preview = vi.fn().mockResolvedValue({
      changed: true as const,
      changeId: 'change-1', expiresIn: 600, expectedConfirmation: 'APPLY', requiresConfirmation: true,
      diff: [{ field: 'enabled', from: 'false', to: 'true' }], consequences: ['Only Hysteria 2 is replaced.'],
      settings: { ...baseStatus, enabled: true, state: 'applying' },
    })
    api.hysteria.status = vi.fn()
      .mockResolvedValueOnce(baseStatus)
      .mockResolvedValueOnce({ ...baseStatus, enabled: true, state: 'on' })
    const wrapper = mount(HysteriaSettingsPanel, { props: { api, language: 'en' } })
    await flushPromises()
    const inputs = wrapper.findAll('input[type="file"]')
    const fullchain = new File(['chain'], 'fullchain.pem')
    const privateKey = new File(['key'], 'privkey.pem')
    for (const [input, file] of [[inputs[0], fullchain], [inputs[1], privateKey]] as const) {
      if (!input) throw new Error('Expected certificate file input')
      Object.defineProperty(input.element, 'files', { configurable: true, value: { item: (index: number) => index === 0 ? file : null } })
      await input.trigger('change')
    }
    await wrapper.findAll('button').find(button => button.text() === 'Validate and stage certificate')?.trigger('click')
    await flushPromises()
    expect(api.hysteria.uploadCertificate).toHaveBeenCalledWith(fullchain, privateKey, 'vpn.example.test')

    await wrapper.get('input[type="checkbox"]').setValue(true)
    await wrapper.findAll('button').find(button => button.text() === 'Review Hysteria 2 changes')?.trigger('click')
    await flushPromises()
    expect(wrapper.find('[role="dialog"]').exists()).toBe(true)
    await wrapper.get('input[autocomplete="off"]').setValue('APPLY')
    const apply = wrapper.findAll('button').find(button => button.text() === 'Apply settings')
    await apply?.trigger('click')
    await flushPromises()
    expect(api.hysteria.apply).toHaveBeenCalledWith('change-1', 'APPLY')
    expect(wrapper.emitted('saved')).toHaveLength(1)
    expect(wrapper.text()).toContain('Running')
  })

  it('keeps current settings when preview has no changes and reports API errors', async () => {
    const api = makeApi()
    const wrapper = mount(HysteriaSettingsPanel, { props: { api, language: 'ru' } })
    await flushPromises()
    const review = wrapper.findAll('button').find(button => button.text() === 'Проверить изменения Hysteria 2')
    await review?.trigger('click')
    await flushPromises()
    expect(wrapper.find('[role="dialog"]').exists()).toBe(false)

    api.hysteria.preview = vi.fn().mockRejectedValue(new Error('invalid timeout'))
    await review?.trigger('click')
    await flushPromises()
    expect(wrapper.emitted('error')?.[0]?.[0]).toMatchObject({ message: 'invalid timeout' })
  })
})

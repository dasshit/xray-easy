import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import ExpirySelector from './ExpirySelector.vue'

describe('ExpirySelector', () => {
  afterEach(() => vi.useRealTimers())

  it('defaults to unlimited lifetime and updates a preset as an UTC instant', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-10-01T12:00:00Z'))
    const wrapper = mount(ExpirySelector, { props: { language: 'en' } })
    await wrapper.get('[data-testid="expiry-preset"]').setValue('24-hours')

    expect(wrapper.get('[data-testid="expiry-preset"]').element).toHaveProperty('value', '24-hours')
    expect(wrapper.emitted('update:modelValue')?.[0]?.[0]).toBe('2026-10-02T12:00:00.000Z')
    expect(wrapper.emitted('validChange')?.at(-1)?.[0]).toBe(true)
    wrapper.unmount()
  })

  it('rejects a past custom value and accepts a future local date', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-10-01T12:00:00Z'))
    const wrapper = mount(ExpirySelector, { props: { language: 'en' } })
    await wrapper.get('[data-testid="expiry-preset"]').setValue('custom')
    await flushPromises()
    const custom = wrapper.get('[data-testid="expiry-custom"]')
    await custom.setValue('2026-09-30T12:00')
    expect(wrapper.emitted('validChange')?.at(-1)?.[0]).toBe(false)
    expect(wrapper.text()).toContain('Choose a future date and time.')

    await custom.setValue('2026-10-04T12:00')
    expect(wrapper.emitted('validChange')?.at(-1)?.[0]).toBe(true)
    expect(wrapper.emitted('update:modelValue')?.at(-1)?.[0]).toBe(new Date('2026-10-04T12:00').toISOString())
  })

  it('publishes no expiry when the unlimited preset is selected', async () => {
    const wrapper = mount(ExpirySelector, { props: { language: 'ru', modelValue: '2026-10-04T12:00:00Z' } })
    await flushPromises()
    await wrapper.get('[data-testid="expiry-preset"]').setValue('never')

    expect(wrapper.emitted('update:modelValue')?.at(-1)?.[0]).toBeUndefined()
    expect(wrapper.emitted('validChange')?.at(-1)?.[0]).toBe(true)
  })
})

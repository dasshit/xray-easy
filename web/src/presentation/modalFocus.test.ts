import { defineComponent, h, withDirectives } from 'vue'
import { mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { modalReturnFocusTarget, releaseModalFocus, vModalFocus } from './modalFocus'

const wrappers: ReturnType<typeof mount>[] = []

function mountDialog(controls: string) {
  const Host = defineComponent({
    setup() {
      return () => withDirectives(
        h('div', { role: 'dialog', tabindex: '-1', innerHTML: controls }),
        [[vModalFocus]],
      )
    },
  })
  const wrapper = mount(Host, { attachTo: document.body })
  wrappers.push(wrapper)
  return wrapper.element as HTMLElement
}

function keydown(dialog: HTMLElement, key: string, shiftKey = false): KeyboardEvent {
  const event = new KeyboardEvent('keydown', { key, shiftKey, bubbles: true, cancelable: true })
  dialog.dispatchEvent(event)
  return event
}

function addOpener(): HTMLButtonElement {
  const opener = document.createElement('button')
  opener.textContent = 'Open dialog'
  document.body.append(opener)
  opener.focus()
  return opener
}

afterEach(() => {
  for (const wrapper of wrappers.splice(0)) wrapper.unmount()
  document.body.replaceChildren()
  vi.restoreAllMocks()
})

describe('modal focus management', () => {
  it('uses the body when the previous focus is not an HTML element', () => {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg')

    expect(modalReturnFocusTarget(svg)).toBe(document.body)
    expect(modalReturnFocusTarget(null)).toBe(document.body)
  })

  it('focuses the first control, wraps both Tab directions, and restores its opener', () => {
    const opener = addOpener()
    const dialog = mountDialog('<button>Close</button><input /><button>Cancel</button>')
    const [first, , last] = dialog.querySelectorAll<HTMLElement>('button, input')

    expect(document.activeElement).toBe(first)

    first?.focus()
    const backwards = keydown(dialog, 'Tab', true)
    expect(backwards.defaultPrevented).toBe(true)
    expect(document.activeElement).toBe(last)

    const forwards = keydown(dialog, 'Tab')
    expect(forwards.defaultPrevented).toBe(true)
    expect(document.activeElement).toBe(first)

    dialog.querySelector('input')?.focus()
    expect(keydown(dialog, 'Tab').defaultPrevented).toBe(false)
    expect(keydown(dialog, 'Tab', true).defaultPrevented).toBe(false)

    wrappers[0]?.unmount()
    wrappers.pop()
    expect(document.activeElement).toBe(opener)
  })

  it('uses an explicitly marked initial control and ignores non-Tab keys', () => {
    const opener = addOpener()
    const dialog = mountDialog('<button>Close</button><input data-modal-autofocus />')
    const input = dialog.querySelector('input')

    expect(document.activeElement).toBe(input)
    expect(keydown(dialog, 'Escape').defaultPrevented).toBe(false)

    wrappers[0]?.unmount()
    wrappers.pop()
    expect(document.activeElement).toBe(opener)
  })

  it('keeps focus on an empty dialog when there are no tabbable controls', () => {
    const dialog = mountDialog('<p>Nothing to focus</p>')

    expect(document.activeElement).toBe(dialog)
    const event = keydown(dialog, 'Tab')
    expect(event.defaultPrevented).toBe(true)
    expect(document.activeElement).toBe(dialog)
  })

  it('does not try to restore focus to an opener removed while the dialog was open', () => {
    const opener = addOpener()
    const dialog = mountDialog('<button>Close</button>')
    const focus = vi.spyOn(opener, 'focus')
    opener.remove()

    wrappers[0]?.unmount()
    wrappers.pop()
    expect(focus).not.toHaveBeenCalled()
    expect(dialog.isConnected).toBe(false)
  })

  it('can release focus management for an element that was never mounted as a dialog', () => {
    expect(() => releaseModalFocus(document.createElement('div'))).not.toThrow()
  })
})

import { afterEach, describe, expect, it } from 'vitest'
import { handleTabListKeydown } from './tabKeyboard'

const tablists: HTMLElement[] = []

function createTablist(options: { direction?: 'ltr' | 'rtl'; disabled?: boolean } = {}) {
  const tablist = document.createElement('div')
  tablist.setAttribute('role', 'tablist')
  if (options.direction !== undefined) tablist.dir = options.direction
  tablist.innerHTML = options.disabled === true
    ? '<button role="tab" disabled>Disabled</button>'
    : '<button role="tab">One</button><button role="tab">Two</button><button role="tab">Three</button>'
  document.body.append(tablist)
  tablists.push(tablist)
  tablist.addEventListener('keydown', handleTabListKeydown)
  return tablist
}

function dispatch(tablist: HTMLElement, target: Element, key: string) {
  const event = new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true })
  target.dispatchEvent(event)
  return event
}

function tabAt(tablist: HTMLElement, index: number): HTMLButtonElement {
  const tabs = tablist.querySelectorAll<HTMLButtonElement>('[role="tab"]')
  const tab = tabs[index]
  if (tab === undefined) throw new Error(`Tab ${index} was not rendered`)
  return tab
}

afterEach(() => {
  for (const tablist of tablists.splice(0)) tablist.remove()
})

describe('tablist keyboard navigation', () => {
  it('activates the next tab and wraps at both ends in left-to-right layouts', () => {
    const tablist = createTablist()
    const first = tabAt(tablist, 0)
    const second = tabAt(tablist, 1)
    const last = tabAt(tablist, 2)

    first.focus()
    expect(dispatch(tablist, first, 'ArrowRight').defaultPrevented).toBe(true)
    expect(document.activeElement).toBe(second)

    expect(dispatch(tablist, second, 'End').defaultPrevented).toBe(true)
    expect(document.activeElement).toBe(last)

    expect(dispatch(tablist, last, 'ArrowRight').defaultPrevented).toBe(true)
    expect(document.activeElement).toBe(first)

    expect(dispatch(tablist, first, 'ArrowLeft').defaultPrevented).toBe(true)
    expect(document.activeElement).toBe(last)

    expect(dispatch(tablist, last, 'Home').defaultPrevented).toBe(true)
    expect(document.activeElement).toBe(first)
  })

  it('reverses horizontal arrows in right-to-left layouts', () => {
    const tablist = createTablist({ direction: 'rtl' })
    const first = tabAt(tablist, 0)
    const last = tabAt(tablist, 2)

    first.focus()
    dispatch(tablist, first, 'ArrowRight')
    expect(document.activeElement).toBe(last)

    dispatch(tablist, last, 'ArrowLeft')
    expect(document.activeElement).toBe(first)
  })

  it('ignores unrelated keys and targets outside a tab', () => {
    const tablist = createTablist()
    const first = tabAt(tablist, 0)
    first.focus()

    expect(dispatch(tablist, first, 'Tab').defaultPrevented).toBe(false)
    expect(dispatch(tablist, tablist, 'ArrowRight').defaultPrevented).toBe(false)
    expect(document.activeElement).toBe(first)
  })

  it('ignores a tablist without enabled tabs and disabled tabs', () => {
    const tablist = createTablist({ disabled: true })
    const disabled = tabAt(tablist, 0)

    expect(dispatch(tablist, disabled, 'ArrowRight').defaultPrevented).toBe(false)
  })

  it('ignores a disabled tab when other enabled tabs are present', () => {
    const tablist = createTablist()
    const disabled = document.createElement('button')
    disabled.setAttribute('role', 'tab')
    disabled.disabled = true
    tablist.append(disabled)

    expect(dispatch(tablist, disabled, 'ArrowRight').defaultPrevented).toBe(false)
  })

  it('ignores keyboard events without a valid tablist or HTML tab target', () => {
    const tablist = createTablist()
    const noCurrentTarget = new KeyboardEvent('keydown', { key: 'ArrowRight' })
    expect(() => handleTabListKeydown(noCurrentTarget)).not.toThrow()

    const noElementTarget = new KeyboardEvent('keydown', { key: 'ArrowRight' })
    Object.defineProperty(noElementTarget, 'currentTarget', { value: tablist })
    Object.defineProperty(noElementTarget, 'target', { value: null })
    expect(() => handleTabListKeydown(noElementTarget)).not.toThrow()

    const svgTab = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
    svgTab.setAttribute('role', 'tab')
    tablist.append(svgTab)
    expect(dispatch(tablist, svgTab, 'ArrowRight').defaultPrevented).toBe(false)
  })
})

import type { ObjectDirective } from 'vue'

const focusableSelector = [
  'a[href]:not([tabindex="-1"])',
  'button:not([disabled]):not([tabindex="-1"])',
  'input:not([disabled]):not([type="hidden"]):not([tabindex="-1"])',
  'select:not([disabled]):not([tabindex="-1"])',
  'textarea:not([disabled]):not([tabindex="-1"])',
  '[tabindex]:not([tabindex="-1"])',
].join(',')

type ModalFocusCleanup = () => void

const modalFocusCleanups = new WeakMap<HTMLElement, ModalFocusCleanup>()

/** Find enabled controls that participate in the dialog's Tab order.
 * @param dialog - The modal dialog element.
 * @returns The dialog's tabbable controls in document order.
 */
function focusableElements(dialog: HTMLElement): HTMLElement[] {
  return Array.from(dialog.querySelectorAll<HTMLElement>(focusableSelector))
}

/** Resolve the element that should receive focus after a dialog closes.
 * @param activeElement - The element focused when the dialog opened.
 * @returns The opener when it is an HTML element, or the document body.
 */
export function modalReturnFocusTarget(activeElement: Element | null): HTMLElement {
  return activeElement instanceof HTMLElement ? activeElement : document.body
}

/** Keep keyboard focus within a modal dialog while the user tabs through it.
 * @param event - The keyboard event to handle.
 * @param dialog - The active dialog element.
 */
export function trapDialogFocus(event: KeyboardEvent, dialog: HTMLElement): void {
  if (event.key !== 'Tab') return

  const elements = focusableElements(dialog)
  const first = elements[0]
  const last = elements[elements.length - 1]

  if (!first || !last) {
    event.preventDefault()
    dialog.focus()
    return
  }

  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault()
    last.focus()
    return
  }

  if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault()
    first.focus()
  }
}

/** Attach keyboard trapping and focus restoration to a dialog element.
 * @param dialog - The modal dialog element.
 * @returns A cleanup function for the dialog lifecycle.
 */
function attachModalFocus(dialog: HTMLElement): ModalFocusCleanup {
  const returnFocusTo = modalReturnFocusTarget(document.activeElement)
  const handleKeydown = (event: KeyboardEvent) => trapDialogFocus(event, dialog)
  dialog.addEventListener('keydown', handleKeydown)

  const first = focusableElements(dialog)[0]
  const initial = dialog.querySelector<HTMLElement>('[data-modal-autofocus]') ?? first ?? dialog
  initial.focus()

  return () => {
    dialog.removeEventListener('keydown', handleKeydown)
    if (returnFocusTo.isConnected) returnFocusTo.focus()
  }
}

/** Release focus management for a dialog when it is removed from the page.
 * @param dialog - The modal dialog element.
 */
export function releaseModalFocus(dialog: HTMLElement): void {
  const cleanup = modalFocusCleanups.get(dialog)
  if (!cleanup) return
  cleanup()
  modalFocusCleanups.delete(dialog)
}

/** Focus the first dialog control and restore focus to its opener on removal. */
export const vModalFocus: ObjectDirective<HTMLElement> = {
  mounted(dialog) {
    modalFocusCleanups.set(dialog, attachModalFocus(dialog))
  },
  unmounted(dialog) {
    releaseModalFocus(dialog)
  },
}

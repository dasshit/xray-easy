/** Move focus and activate a tab with the standard tablist keyboard controls.
 * @param event - The key event bubbling from the tablist.
 */
export function handleTabListKeydown(event: KeyboardEvent): void {
  if (!['ArrowRight', 'ArrowLeft', 'Home', 'End'].includes(event.key)) return

  const currentTarget = event.currentTarget
  if (!(currentTarget instanceof HTMLElement)) return
  const tablist = currentTarget
  const eventTarget = event.target
  if (!(eventTarget instanceof Element)) return
  const activeTabCandidate = eventTarget.closest('[role="tab"]')
  if (!(activeTabCandidate instanceof HTMLElement)) return
  const activeTab = activeTabCandidate
  const tabs = Array.from(tablist.querySelectorAll<HTMLElement>('[role="tab"]:not([disabled])'))
  if (tabs.length === 0) return

  const activeIndex = tabs.indexOf(activeTab)
  if (activeIndex < 0) return

  const direction = getComputedStyle(tablist).direction
  const visualNext = direction === 'rtl' ? -1 : 1
  let nextIndex: number

  if (event.key === 'Home') nextIndex = 0
  else if (event.key === 'End') nextIndex = tabs.length - 1
  else if (event.key === 'ArrowRight') nextIndex = (activeIndex + visualNext + tabs.length) % tabs.length
  else nextIndex = (activeIndex - visualNext + tabs.length) % tabs.length

  event.preventDefault()
  const nextTab = tabs[nextIndex]
  nextTab?.focus()
  nextTab?.click()
}

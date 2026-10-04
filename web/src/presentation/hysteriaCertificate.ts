import type { HysteriaCertificateInfo } from '../application/models'
import type { UILanguage } from './i18n'

/**
 * Format the active certificate expiry using the selected interface language.
 * @param certificate - The certificate whose expiration is displayed.
 * @param language - The locale used for the date.
 * @returns A localized date or an em dash when no certificate exists.
 */
export function formatCertificateExpiry(certificate: HysteriaCertificateInfo | null | undefined, language: UILanguage): string {
  if (!certificate) return '—'
  return new Intl.DateTimeFormat(language, { dateStyle: 'medium' }).format(new Date(certificate.notAfter))
}

/** Return the first selected file from a native file input, or null for an empty/non-input event.
 * @param target - The event target to inspect.
 * @returns The selected file, or null when there is no file input or selection.
 */
export function selectedCertificateFile(target: EventTarget | null): File | null {
  if (!(target instanceof HTMLInputElement)) return null
  return target.files?.item(0) ?? null
}

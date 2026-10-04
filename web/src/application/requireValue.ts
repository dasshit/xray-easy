/** Return a required value or throw a descriptive error when the UI invariant is broken.
 * @param value - The possibly absent value.
 * @param label - The name used in the error message.
 * @returns The present value.
 * @throws {Error} When the value is null or undefined.
 */
export function requireValue<T>(value: T | null | undefined, label: string): T {
  if (value === null || value === undefined) throw new Error(`${label} is unavailable`)
  return value
}

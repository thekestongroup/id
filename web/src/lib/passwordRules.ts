import type { PasswordRule } from './api'

/**
 * Whether a password meets a rule, counted the way the server does
 * (internal/policy): capitals, lowercase, digits, and "special" is anything
 * else that isn't a space. "common" (banned phrases, the common-passwords
 * list) can't be checked here, so it's left to the server, and counts as met.
 */
export function ruleMet(rule: PasswordRule, password: string): boolean {
  const chars = [...password]
  const count = (re: RegExp) => chars.filter((c) => re.test(c)).length
  switch (rule.id) {
    case 'length':
      return chars.length >= (rule.min ?? 0) && chars.length <= 256
    case 'uppercase':
      return count(/\p{Lu}/u) >= (rule.min ?? 0)
    case 'lowercase':
      return count(/\p{Ll}/u) >= (rule.min ?? 0)
    case 'digits':
      return count(/\p{Nd}/u) >= (rule.min ?? 0)
    case 'special':
      return count(/[^\p{Lu}\p{Ll}\p{Nd}\s]/u) >= (rule.min ?? 0)
    default:
      return true
  }
}

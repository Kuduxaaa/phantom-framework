/**
 * Time-related helpers for relative-date formatting and date construction.
 */

/**
 * Build a Date `mins` minutes in the past relative to now.
 */
export function ago(mins: number): Date {
  return new Date(Date.now() - mins * 60_000)
}

/**
 * Format a Date as a short, human-friendly relative string ("8m ago", "2d ago", "May 14").
 */
export function fmtRel(d: Date): string {
  const m = Math.round((Date.now() - d.getTime()) / 60_000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.round(m / 60)
  if (h < 24) return `${h}h ago`
  const days = Math.round(h / 24)
  if (days < 7) return `${days}d ago`
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
}

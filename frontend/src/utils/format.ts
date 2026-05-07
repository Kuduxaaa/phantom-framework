/**
 * Formatting helpers for raw values shown in the UI.
 */

import type { HttpMethod } from '@/types'

/**
 * Render a byte count as a compact human-readable string ("523B", "12.3K", "4.2M").
 */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}K`
  return `${(bytes / 1024 / 1024).toFixed(1)}M`
}

/**
 * Map an HTTP method to the corresponding CSS variable used for its accent color.
 */
export function methodColor(method: HttpMethod | string): string {
  const key = method.toUpperCase()
  const map: Record<string, string> = {
    GET: 'var(--m-get)',
    POST: 'var(--m-post)',
    PUT: 'var(--m-put)',
    DELETE: 'var(--m-delete)',
    PATCH: 'var(--m-patch)',
    OPTIONS: 'var(--m-other)',
    HEAD: 'var(--m-other)',
  }
  return map[key] ?? 'var(--m-other)'
}

/**
 * Pick a status-class color for an HTTP response code.
 */
export function statusColor(status: number): string {
  if (status >= 500) return 'var(--err)'
  if (status >= 400) return 'var(--warn)'
  if (status >= 300) return 'var(--sev-info)'
  return 'var(--ok)'
}

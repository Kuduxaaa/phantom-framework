/**
 * Bind a keyboard shortcut for the lifetime of the calling component.
 *
 * The handler receives the original `KeyboardEvent` and is responsible for
 * `preventDefault` if needed.
 */

import { onMounted, onBeforeUnmount } from 'vue'

export interface KeybindingOptions {
  meta?: boolean
  ctrl?: boolean
  metaOrCtrl?: boolean
  shift?: boolean
  alt?: boolean
}

function matches(event: KeyboardEvent, key: string, opts: KeybindingOptions): boolean {
  if (event.key.toLowerCase() !== key.toLowerCase()) return false
  if (opts.meta && !event.metaKey) return false
  if (opts.ctrl && !event.ctrlKey) return false
  if (opts.metaOrCtrl && !(event.metaKey || event.ctrlKey)) return false
  if (opts.shift && !event.shiftKey) return false
  if (opts.alt && !event.altKey) return false
  return true
}

export function useKeybinding(
  key: string,
  handler: (event: KeyboardEvent) => void,
  opts: KeybindingOptions = {},
): void {
  function onKeyDown(event: KeyboardEvent): void {
    if (matches(event, key, opts)) handler(event)
  }
  onMounted(() => window.addEventListener('keydown', onKeyDown))
  onBeforeUnmount(() => window.removeEventListener('keydown', onKeyDown))
}

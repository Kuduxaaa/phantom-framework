/**
 * Proxy store — captured HTTP/HTTPS traffic and the active selection.
 */

import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { proxyTraffic as seed } from '@/data/mock'
import type { ProxyEntry } from '@/types'

export const useProxyStore = defineStore('proxy', () => {
  const items = ref<ProxyEntry[]>(seed)
  const selectedId = ref<number | null>(seed[3]?.id ?? null)
  const paused = ref<boolean>(false)

  const selected = computed<ProxyEntry | undefined>(() =>
    items.value.find((t) => t.id === selectedId.value),
  )

  const intercepted = computed<ProxyEntry[]>(() =>
    items.value.filter((t) => t.intercepted),
  )

  const errors = computed<number>(() =>
    items.value.filter((t) => t.status >= 400).length,
  )

  function select(id: number | null): void {
    selectedId.value = id
  }

  function clearSelection(): void {
    selectedId.value = null
  }

  function togglePause(): void {
    paused.value = !paused.value
  }

  return {
    items,
    selectedId,
    selected,
    intercepted,
    errors,
    paused,
    select,
    clearSelection,
    togglePause,
  }
})

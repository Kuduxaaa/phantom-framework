/**
 * Targets store — discovered hosts within the active vault.
 */

import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { targets as seed } from '@/data/mock'
import type { Target } from '@/types'

export const useTargetsStore = defineStore('targets', () => {
  const items = ref<Target[]>(seed)
  const activeId = ref<number>(seed[0]?.id ?? 0)

  const active = computed<Target | undefined>(() =>
    items.value.find((t) => t.id === activeId.value),
  )

  function setActive(id: number): void {
    activeId.value = id
  }

  function byId(id: number): Target | undefined {
    return items.value.find((t) => t.id === id)
  }

  return { items, activeId, active, setActive, byId }
})

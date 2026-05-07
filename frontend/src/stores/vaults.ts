/**
 * Vault store — bug bounty programs.
 */

import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { vaults as seed } from '@/data/mock'
import type { Vault } from '@/types'

export const useVaultsStore = defineStore('vaults', () => {
  const items = ref<Vault[]>(seed)
  const activeId = ref<number>(seed[0]?.id ?? 0)

  const active = computed<Vault | undefined>(() =>
    items.value.find((v) => v.id === activeId.value),
  )

  function setActive(id: number): void {
    activeId.value = id
  }

  return { items, activeId, active, setActive }
})

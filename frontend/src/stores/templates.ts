/**
 * Signature templates store.
 */

import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { templates as seed, templateYaml } from '@/data/mock'
import type { SignatureTemplate } from '@/types'

export const useTemplatesStore = defineStore('templates', () => {
  const items = ref<SignatureTemplate[]>(seed)
  const yaml = ref<string>(templateYaml)
  const activeId = ref<string>(seed[0]?.id ?? '')

  const active = computed<SignatureTemplate | undefined>(() =>
    items.value.find((t) => t.id === activeId.value),
  )

  const grouped = computed<Record<string, SignatureTemplate[]>>(() => {
    const acc: Record<string, SignatureTemplate[]> = {}
    for (const t of items.value) {
      ;(acc[t.category] ??= []).push(t)
    }
    return acc
  })

  function setActive(id: string): void {
    activeId.value = id
  }

  return { items, yaml, activeId, active, grouped, setActive }
})

/**
 * Findings store — vulnerabilities and security issues with triage state.
 */

import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { findings as seed } from '@/data/mock'
import type { Finding } from '@/types'

export const useFindingsStore = defineStore('findings', () => {
  const items = ref<Finding[]>(seed)
  const inspectedId = ref<number | null>(null)

  const inspected = computed<Finding | null>(() =>
    items.value.find((f) => f.id === inspectedId.value) ?? null,
  )

  function inspect(id: number | null): void {
    inspectedId.value = id
  }

  function byTarget(targetId: number): Finding[] {
    return items.value.filter((f) => f.target_id === targetId)
  }

  return { items, inspectedId, inspected, inspect, byTarget }
})

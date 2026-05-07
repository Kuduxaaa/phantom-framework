<script setup lang="ts">
/**
 * Findings view — cross-target severity-sorted list with filters and inspector.
 */
import { computed, ref } from 'vue'
import PSecondaryNav from '@/components/organisms/PSecondaryNav.vue'
import PMainPanel from '@/components/organisms/PMainPanel.vue'
import PFindingsTable from '@/components/organisms/PFindingsTable.vue'
import PFindingInspector from '@/components/organisms/PFindingInspector.vue'
import PFilterGroup from '@/components/molecules/PFilterGroup.vue'
import PPanelHeader from '@/components/molecules/PPanelHeader.vue'
import PSeverityBadge from '@/components/atoms/PSeverityBadge.vue'
import PButton from '@/components/atoms/PButton.vue'
import PIcon from '@/components/atoms/PIcon.vue'
import { useFindingsStore } from '@/stores/findings'
import type { Finding, Severity } from '@/types'

const findings = useFindingsStore()

const sev = ref<string>('all')
const status = ref<string>('all')

const SEV_OPTIONS = ['all', 'critical', 'high', 'medium', 'low', 'info'] as const
const STATUS_OPTIONS = ['all', 'new', 'triaging', 'validated', 'reported', 'resolved'] as const

const filtered = computed<Finding[]>(() =>
  findings.items.filter((f) => {
    const okSev = sev.value === 'all' || f.severity.toLowerCase() === sev.value
    const okStatus = status.value === 'all' || f.status.toLowerCase() === status.value
    return okSev && okStatus
  }),
)

const sevCounts = computed<Record<string, number>>(() => {
  const acc: Record<string, number> = {}
  for (const k of ['critical', 'high', 'medium', 'low', 'info']) {
    acc[k] = findings.items.filter((f) => f.severity.toLowerCase() === k).length
  }
  return acc
})

function inspect(f: Finding): void {
  findings.inspect(f.id)
}
</script>

<template>
  <PSecondaryNav title="Filters" :footer="`${filtered.length} of ${findings.items.length} findings`">
    <PFilterGroup
      v-model="sev"
      label="Severity"
      :options="SEV_OPTIONS"
      :counts="sevCounts"
    >
      <template #option="{ value }">
        <span v-if="value === 'all'">All</span>
        <PSeverityBadge v-else :level="value as Severity | Lowercase<Severity>" variant="dot" />
      </template>
    </PFilterGroup>

    <PFilterGroup v-model="status" label="Status" :options="STATUS_OPTIONS" />
  </PSecondaryNav>

  <PMainPanel>
    <PPanelHeader
      :breadcrumb="[{ label: 'Acme Corp' }, { label: 'Findings' }]"
      title="Findings"
    >
      <template #subtitle>{{ filtered.length }} matched · sorted by severity</template>
      <template #actions>
        <PButton variant="ghost"><template #icon><PIcon name="filter" :size="12" /></template>More filters</PButton>
        <PButton variant="secondary"><template #icon><PIcon name="external" :size="12" /></template>Export</PButton>
      </template>
    </PPanelHeader>

    <div class="p-findings__body">
      <PFindingsTable :findings="filtered" @select="inspect" />
    </div>
  </PMainPanel>

  <PFindingInspector />
</template>

<style scoped>
.p-findings__body {
  flex: 1;
  overflow-y: auto;
  min-width: 0;
}
</style>

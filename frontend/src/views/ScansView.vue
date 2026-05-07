<script setup lang="ts">
/**
 * Scans view — scan history sidebar + live streaming terminal output.
 *
 * The terminal reveals lines on a randomized cadence via `useScanStream` and
 * supports pause/resume + level filtering.
 */
import { computed, nextTick, ref, watch } from 'vue'
import PSecondaryNav from '@/components/organisms/PSecondaryNav.vue'
import PMainPanel from '@/components/organisms/PMainPanel.vue'
import PNavRow from '@/components/molecules/PNavRow.vue'
import PPanelHeader from '@/components/molecules/PPanelHeader.vue'
import PScanLine from '@/components/molecules/PScanLine.vue'
import PRunningPulse from '@/components/atoms/PRunningPulse.vue'
import PIcon from '@/components/atoms/PIcon.vue'
import PButton from '@/components/atoms/PButton.vue'
import PFilterChip from '@/components/atoms/PFilterChip.vue'
import { useScanStream } from '@/composables/useScanStream'
import { scanStream } from '@/data/mock'
import type { ScanLineLevel } from '@/types'

type StreamFilter = 'all' | 'matches' | 'info' | 'critical'

const FILTERS: StreamFilter[] = ['all', 'matches', 'info', 'critical']
const MATCH_LEVELS: ScanLineLevel[] = ['critical', 'high', 'medium', 'low']

const { visible, visibleCount, running, isComplete, progress, toggle } = useScanStream(scanStream)
const filter = ref<StreamFilter>('all')
const containerRef = ref<HTMLDivElement | null>(null)

const filtered = computed(() =>
  visible.value.filter((l) => {
    if (filter.value === 'all') return true
    if (filter.value === 'matches') return MATCH_LEVELS.includes(l.level)
    return l.level === filter.value
  }),
)

const counts = computed(() => ({
  critical: visible.value.filter((l) => l.level === 'critical').length,
  high: visible.value.filter((l) => l.level === 'high').length,
  medium: visible.value.filter((l) => l.level === 'medium').length,
  low: visible.value.filter((l) => l.level === 'low').length,
}))

const elapsed = computed<string>(() => `${(visibleCount.value * 0.7).toFixed(1)}s`)

watch(visibleCount, () => {
  void nextTick(() => {
    if (containerRef.value) containerRef.value.scrollTop = containerRef.value.scrollHeight
  })
})
</script>

<template>
  <PSecondaryNav title="Scan history" footer="1 active · 47 total">
    <PNavRow
      active
      label="api.acme.io · #9001"
      :sub="isComplete ? 'completed' : `running ${visibleCount}/${scanStream.length}`"
    >
      <template #leading><PRunningPulse :paused="!running" /></template>
    </PNavRow>
    <PNavRow label="acme.com · #9000" sub="completed · 9.2s">
      <template #leading><PIcon name="check" :size="12" /></template>
    </PNavRow>
    <PNavRow label="*.acme.com · #8999" sub="completed · 4m ago">
      <template #leading><PIcon name="check" :size="12" /></template>
    </PNavRow>
    <PNavRow label="staging-api · #8995" sub="failed · 5h ago">
      <template #leading><PIcon name="close" :size="12" /></template>
    </PNavRow>
    <PNavRow label="auth.acme.com · #8990" sub="completed · 1d ago">
      <template #leading><PIcon name="check" :size="12" /></template>
    </PNavRow>
  </PSecondaryNav>

  <PMainPanel>
    <PPanelHeader
      :breadcrumb="[{ label: 'Scans' }, { label: '#9001' }]"
      title="vulnerability_scan · api.acme.io"
    >
      <template #subtitle>
        <span class="p-scans__subtitle">
          <span>started 14:02:18 · {{ isComplete ? 'completed in 16.4s' : `${elapsed} elapsed` }}</span>
          <span class="p-scans__sep">·</span>
          <span class="p-scans__mono">26 templates · 23 params</span>
        </span>
      </template>
      <template #actions>
        <PButton v-if="!isComplete" variant="ghost" @click="toggle">
          <template #icon>
            <PIcon :name="running ? 'pause' : 'play'" :size="12" />
          </template>
          {{ running ? 'Pause' : 'Resume' }}
        </PButton>
        <PButton variant="ghost"><template #icon><PIcon name="stop" :size="12" /></template>Cancel</PButton>
        <PButton variant="secondary"><template #icon><PIcon name="external" :size="12" /></template>Findings</PButton>
      </template>
    </PPanelHeader>

    <div class="p-scans__progress">
      <div class="p-scans__progress-row">
        <span class="label">Progress</span>
        <span class="tabular p-scans__progress-text">{{ visibleCount }}/{{ scanStream.length }} steps</span>
        <span class="p-scans__spacer" />
        <span
          v-for="sev in (['critical', 'high', 'medium', 'low'] as const)"
          :key="sev"
          class="p-scans__count"
          :style="{ color: counts[sev] > 0 ? `var(--sev-${sev})` : 'var(--fg-faint)' }"
        >
          <span
            class="p-scans__count-dot"
            :style="{ background: counts[sev] > 0 ? `var(--sev-${sev})` : 'var(--line-strong)' }"
          />
          {{ counts[sev] }} {{ sev }}
        </span>
      </div>
      <div class="p-scans__bar">
        <div
          class="p-scans__bar-fill"
          :style="{
            width: `${progress}%`,
            background: isComplete ? 'var(--ok)' : 'var(--accent)',
          }"
        />
      </div>
    </div>

    <div class="p-scans__filter-bar">
      <span class="label p-scans__filter-label">View</span>
      <PFilterChip
        v-for="f in FILTERS"
        :key="f"
        variant="flat"
        :active="filter === f"
        @click="filter = f"
      >{{ f }}</PFilterChip>
      <span class="p-scans__spacer" />
      <span class="p-scans__filter-meta">{{ filtered.length }} lines</span>
    </div>

    <div ref="containerRef" class="p-scans__terminal">
      <PScanLine v-for="(line, i) in filtered" :key="i" :line="line" />
      <div v-if="!isComplete && running && filter === 'all'" class="p-scans__cursor-row">
        <span></span>
        <span></span>
        <span class="p-scans__cursor" />
      </div>
    </div>
  </PMainPanel>
</template>

<style scoped>
.p-scans__subtitle {
  display: inline-flex;
  align-items: center;
  gap: 10px;
}

.p-scans__sep {
  color: var(--fg-faint);
}

.p-scans__mono {
  font-family: var(--font-mono);
}

.p-scans__progress {
  border-bottom: 1px solid var(--line);
  padding: 12px 20px;
  background: var(--bg);
}

.p-scans__progress-row {
  display: flex;
  align-items: center;
  gap: 14px;
  margin-bottom: 10px;
}

.p-scans__progress-text {
  font-size: var(--t-sm);
  color: var(--fg);
  font-family: var(--font-mono);
}

.p-scans__spacer {
  flex: 1;
}

.p-scans__count {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-size: var(--t-xs);
  text-transform: uppercase;
  letter-spacing: var(--tracking-label);
  font-weight: 500;
  font-variant-numeric: tabular-nums;
}

.p-scans__count-dot {
  width: 5px;
  height: 5px;
  border-radius: 999px;
}

.p-scans__bar {
  height: 2px;
  background: var(--line-soft);
  border-radius: 999px;
  overflow: hidden;
}

.p-scans__bar-fill {
  height: 100%;
  transition:
    width 200ms linear,
    background 200ms var(--ease);
}

.p-scans__filter-bar {
  display: flex;
  gap: 4px;
  padding: 8px 20px;
  border-bottom: 1px solid var(--line);
  align-items: center;
}

.p-scans__filter-label {
  margin-right: 8px;
}

.p-scans__filter-meta {
  font-family: var(--font-mono);
  font-size: var(--t-xs);
  color: var(--fg-faint);
}

.p-scans__terminal {
  flex: 1;
  overflow-y: auto;
  padding: 8px 0;
  background: var(--bg-sunken);
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.65;
}

.p-scans__cursor-row {
  display: grid;
  grid-template-columns: 90px 60px 1fr;
  padding: 1px 20px;
}

.p-scans__cursor {
  width: 7px;
  height: 13px;
  background: var(--accent);
  display: inline-block;
  animation: phBlink 1s steps(2, end) infinite;
}
</style>

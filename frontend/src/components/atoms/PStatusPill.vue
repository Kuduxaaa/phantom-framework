<script setup lang="ts">
/**
 * Triage status pill for findings — soft monochrome with a single colored cue.
 */
import { computed } from 'vue'
import type { FindingStatus } from '@/types'

interface Props {
  status: FindingStatus
}

const props = defineProps<Props>()

interface PillTones {
  fg: string
  dot: string
}

const TONES: Record<FindingStatus, PillTones> = {
  NEW: { fg: 'var(--fg)', dot: 'var(--fg-faint)' },
  TRIAGING: { fg: 'var(--sev-medium)', dot: 'var(--sev-medium)' },
  VALIDATED: { fg: 'var(--accent)', dot: 'var(--accent)' },
  REPORTED: { fg: 'var(--sev-info)', dot: 'var(--sev-info)' },
  ACCEPTED: { fg: 'var(--ok)', dot: 'var(--ok)' },
  RESOLVED: { fg: 'var(--ok)', dot: 'var(--ok)' },
  DUPLICATE: { fg: 'var(--fg-subtle)', dot: 'var(--fg-faint)' },
  FALSE_POSITIVE: { fg: 'var(--fg-subtle)', dot: 'var(--fg-faint)' },
  WONT_FIX: { fg: 'var(--fg-subtle)', dot: 'var(--fg-faint)' },
}

const tone = computed<PillTones>(() => TONES[props.status])
const label = computed<string>(() => props.status.replace('_', ' ').toLowerCase())
</script>

<template>
  <span
    class="pill p-status-pill"
    :style="{ color: tone.fg, borderColor: 'var(--line-strong)' }"
  >
    <span class="pill-dot" :style="{ background: tone.dot }" />
    {{ label }}
  </span>
</template>

<style scoped>
.p-status-pill {
  background: transparent;
  text-transform: capitalize;
  font-weight: 500;
}
</style>

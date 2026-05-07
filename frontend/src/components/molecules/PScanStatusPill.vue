<script setup lang="ts">
/**
 * Lowercase, monochrome status indicator for scan execution states.
 */
import { computed } from 'vue'
import type { ScanStatus } from '@/types'

interface Props {
  status: ScanStatus
}

const props = defineProps<Props>()

const COLOR_MAP: Record<ScanStatus, string> = {
  QUEUED: 'var(--fg-subtle)',
  RUNNING: 'var(--accent)',
  COMPLETED: 'var(--ok)',
  PAUSED: 'var(--warn)',
  FAILED: 'var(--err)',
  CANCELLED: 'var(--fg-subtle)',
}

const color = computed<string>(() => COLOR_MAP[props.status])
const label = computed<string>(() => props.status.toLowerCase())
</script>

<template>
  <span class="p-scan-status-pill" :style="{ color }">{{ label }}</span>
</template>

<style scoped>
.p-scan-status-pill {
  font-size: var(--t-xs);
  text-transform: uppercase;
  letter-spacing: var(--tracking-label);
  font-weight: 500;
}
</style>

<script setup lang="ts">
/**
 * Single line in the live scan terminal — timestamp, level, body.
 *
 * Match-level lines (critical/high/medium/low) get a subtle severity-tinted
 * leading gradient to make them stand out without "hacker glow".
 */
import { computed } from 'vue'
import type { ScanLine } from '@/types'

interface Props {
  line: ScanLine
}

const props = defineProps<Props>()

const isMatch = computed<boolean>(() =>
  ['critical', 'high', 'medium', 'low'].includes(props.line.level),
)

const levelColor = computed<string>(() => {
  if (props.line.level === 'info') return 'var(--fg-muted)'
  return `var(--sev-${props.line.level})`
})

const rowBackground = computed<string>(() => {
  if (!isMatch.value) return 'transparent'
  return `linear-gradient(90deg, var(--sev-${props.line.level}-bg), transparent 240px)`
})
</script>

<template>
  <div class="p-scan-line" :style="{ background: rowBackground }">
    <span class="p-scan-line__ts">{{ line.ts }}</span>
    <span class="p-scan-line__level" :style="{ color: levelColor }">
      {{ line.level === 'info' ? '·' : line.level }}
    </span>
    <span class="p-scan-line__text" :class="{ 'is-match': isMatch }">{{ line.text }}</span>
  </div>
</template>

<style scoped>
.p-scan-line {
  display: grid;
  grid-template-columns: 90px 60px 1fr;
  padding: 1px 20px;
  align-items: baseline;
}

.p-scan-line__ts {
  color: var(--fg-faint);
  font-size: 11px;
}

.p-scan-line__level {
  font-size: 9px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: var(--tracking-label);
}

.p-scan-line__text {
  color: var(--fg-muted);
}

.p-scan-line__text.is-match {
  color: var(--fg);
}
</style>

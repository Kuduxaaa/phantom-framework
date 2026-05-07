<script setup lang="ts">
/**
 * Compact risk-score visualization — a thin bar with the numeric score beside it.
 *
 * Color tracks the score band (low → critical) with the standard severity palette.
 */
import { computed } from 'vue'

interface Props {
  score?: number
  width?: number
}

const props = withDefaults(defineProps<Props>(), {
  score: 0,
  width: 80,
})

const pct = computed<number>(() => Math.max(0, Math.min(100, props.score)))

const color = computed<string>(() => {
  const v = pct.value
  if (v >= 75) return 'var(--sev-critical)'
  if (v >= 50) return 'var(--sev-high)'
  if (v >= 25) return 'var(--sev-medium)'
  return 'var(--sev-low)'
})
</script>

<template>
  <div class="p-risk-meter">
    <div class="p-risk-meter__track" :style="{ width: `${width}px` }">
      <div class="p-risk-meter__fill" :style="{ width: `${pct}%`, background: color }" />
    </div>
    <span class="p-risk-meter__value tabular">{{ pct }}</span>
  </div>
</template>

<style scoped>
.p-risk-meter {
  display: inline-flex;
  align-items: center;
  gap: 8px;
}

.p-risk-meter__track {
  height: 3px;
  background: var(--line);
  border-radius: 999px;
  overflow: hidden;
}

.p-risk-meter__fill {
  height: 100%;
  transition: width 400ms var(--ease-out);
}

.p-risk-meter__value {
  font-size: var(--t-xs);
  color: var(--fg-muted);
  min-width: 22px;
}
</style>

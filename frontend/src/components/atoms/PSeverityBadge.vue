<script setup lang="ts">
/**
 * Severity indicator — Linear-style colored dot with capitalized label.
 *
 * Two presentations:
 *   - `dot`  → just dot + text, no chip background. Use inline.
 *   - `pill` → tinted pill with border + dot + text. Use in tables.
 */
import { computed } from 'vue'
import type { Severity } from '@/types'

interface Props {
  level: Severity | Lowercase<Severity>
  variant?: 'pill' | 'dot'
  size?: 'sm' | 'lg'
}

const props = withDefaults(defineProps<Props>(), {
  variant: 'pill',
  size: 'sm',
})

const lower = computed<string>(() => String(props.level).toLowerCase())

const pillStyle = computed(() => ({
  background: `var(--sev-${lower.value}-bg)`,
  color: `var(--sev-${lower.value})`,
  borderColor: `var(--sev-${lower.value}-bd)`,
  height: props.size === 'lg' ? '22px' : '20px',
}))

const dotColor = computed<string>(() => `var(--sev-${lower.value})`)
</script>

<template>
  <span v-if="variant === 'dot'" class="p-severity-dot">
    <span class="p-severity-dot__mark" :style="{ background: dotColor }" />
    {{ lower }}
  </span>
  <span v-else class="pill p-severity-badge" :style="pillStyle">
    <span class="pill-dot" :style="{ background: dotColor }" />
    {{ lower }}
  </span>
</template>

<style scoped>
.p-severity-dot {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 11px;
  color: var(--fg-muted);
  font-variant-numeric: tabular-nums;
  text-transform: capitalize;
  font-weight: 500;
}

.p-severity-dot__mark {
  width: 7px;
  height: 7px;
  border-radius: 2px;
  flex-shrink: 0;
}

.p-severity-badge {
  text-transform: capitalize;
}
</style>

<script setup lang="ts">
/**
 * HTTP method label — colored mono pill for tables, headers, and proxy detail.
 *
 * `variant`:
 *   - `chip`   → solid background when active, outlined otherwise (filter use)
 *   - `inline` → just colored text, no background (table cells)
 */
import { computed } from 'vue'
import { methodColor } from '@/utils/format'
import type { HttpMethod } from '@/types'

interface Props {
  method: HttpMethod | string
  variant?: 'chip' | 'inline'
  active?: boolean
}

const props = withDefaults(defineProps<Props>(), {
  variant: 'inline',
  active: false,
})

const color = computed<string>(() => methodColor(props.method))
</script>

<template>
  <span
    v-if="variant === 'inline'"
    class="p-method-chip p-method-chip--inline"
    :style="{ color }"
  >{{ method }}</span>
  <button
    v-else
    type="button"
    class="p-method-chip p-method-chip--chip"
    :class="{ 'is-active': active }"
    :style="active ? { background: color, color: 'var(--accent-text)', borderColor: 'transparent' } : { color, borderColor: 'var(--line)' }"
  >{{ method }}</button>
</template>

<style scoped>
.p-method-chip {
  font-family: var(--font-mono);
  font-weight: 600;
}

.p-method-chip--inline {
  font-size: 11px;
}

.p-method-chip--chip {
  height: 22px;
  padding: 0 6px;
  font-size: 10.5px;
  border-radius: var(--r-1);
  border: 1px solid transparent;
  background: transparent;
}
</style>

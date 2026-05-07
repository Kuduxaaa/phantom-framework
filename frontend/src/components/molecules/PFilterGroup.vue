<script setup lang="ts">
/**
 * Vertical list of mutually-exclusive filter options under a labeled header.
 *
 * Generic over option value (`string`). Optional `counts` map shows count
 * badges next to non-`all` options. Use the `option` slot to customize the
 * row content (e.g., severity dot + label).
 */

interface Props {
  label: string
  options: readonly string[]
  modelValue: string
  counts?: Record<string, number>
}

defineProps<Props>()

defineEmits<{ 'update:modelValue': [value: string] }>()

function capitalize(s: string): string {
  if (s === 'all') return 'All'
  return s[0]!.toUpperCase() + s.slice(1)
}
</script>

<template>
  <div class="p-filter-group">
    <div class="label p-filter-group__label">{{ label }}</div>
    <button
      v-for="opt in options"
      :key="opt"
      type="button"
      class="p-filter-group__option"
      :class="{ 'is-active': modelValue === opt }"
      @click="$emit('update:modelValue', opt)"
    >
      <span class="p-filter-group__option-content">
        <slot name="option" :value="opt">
          {{ capitalize(opt) }}
        </slot>
      </span>
      <span
        v-if="counts && opt !== 'all'"
        class="tabular p-filter-group__count"
      >{{ counts[opt] ?? 0 }}</span>
    </button>
  </div>
</template>

<style scoped>
.p-filter-group {
  margin-bottom: 16px;
  padding: 4px;
}

.p-filter-group__label {
  padding: 0 6px 6px;
}

.p-filter-group__option {
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
  padding: 4px 8px;
  border-radius: var(--r-2);
  color: var(--fg);
  text-align: left;
  background: transparent;
}

.p-filter-group__option:hover {
  background: var(--hover);
}

.p-filter-group__option.is-active {
  background: var(--active);
}

.p-filter-group__option-content {
  font-size: var(--t-sm);
}

.p-filter-group__count {
  font-size: var(--t-xs);
  color: var(--fg-subtle);
}
</style>

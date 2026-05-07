<script setup lang="ts">
/**
 * Compact key/value cell used inside meta strips and inspector overviews.
 */

interface Props {
  label: string
  value: string | number
  divider?: boolean
}

defineProps<Props>()
</script>

<template>
  <div class="p-key-value" :class="{ 'has-divider': divider }">
    <div class="label p-key-value__label">{{ label }}</div>
    <div class="p-key-value__value">{{ value }}</div>
  </div>
</template>

<style scoped>
.p-key-value {
  padding: 10px 14px;
}

.p-key-value.has-divider {
  border-left: 1px solid var(--line);
}

.p-key-value__label {
  margin-bottom: 4px;
}

.p-key-value__value {
  font-size: var(--t-md);
  color: var(--fg);
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
  text-transform: capitalize;
}
</style>

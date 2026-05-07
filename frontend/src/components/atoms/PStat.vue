<script setup lang="ts">
/**
 * Single stat cell — uppercase label over a prominent value.
 *
 * Use inside grid rows; pass `divider` to render a left hairline separator.
 */

interface Props {
  label: string
  value: string | number
  valueColor?: string
  divider?: boolean
  mono?: boolean
}

withDefaults(defineProps<Props>(), {
  mono: true,
})
</script>

<template>
  <div class="p-stat" :class="{ 'has-divider': divider }">
    <div class="label p-stat__label">{{ label }}</div>
    <div
      class="p-stat__value"
      :class="{ 'is-mono': mono, 'is-prose': !mono }"
      :style="{ color: valueColor || 'var(--fg)' }"
    >
      {{ value }}
    </div>
  </div>
</template>

<style scoped>
.p-stat {
  padding: 14px 18px;
}

.p-stat.has-divider {
  border-left: 1px solid var(--line);
}

.p-stat__label {
  margin-bottom: 4px;
}

.p-stat__value {
  line-height: 1.1;
  font-variant-numeric: tabular-nums;
}

.p-stat__value.is-mono {
  font-family: var(--font-mono);
  font-size: 22px;
  font-weight: 500;
}

.p-stat__value.is-prose {
  font-family: var(--font-display);
  font-size: 18px;
  font-weight: 400;
}
</style>

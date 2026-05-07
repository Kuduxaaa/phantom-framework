<script setup lang="ts">
/**
 * Single filter chip used in inline chip groups.
 *
 * Two visual modes:
 *   - `pill`     → rounded pill with hover-tinted background. Default.
 *   - `flat`     → rectangular chip with active-state tint. Use in compact toolbars.
 */

interface Props {
  active?: boolean
  variant?: 'pill' | 'flat'
}

withDefaults(defineProps<Props>(), {
  active: false,
  variant: 'pill',
})

defineEmits<{ click: [] }>()
</script>

<template>
  <button
    type="button"
    class="p-filter-chip"
    :class="[`p-filter-chip--${variant}`, { 'is-active': active }]"
    @click="$emit('click')"
  >
    <slot />
  </button>
</template>

<style scoped>
.p-filter-chip {
  font-weight: 500;
  text-transform: capitalize;
  color: var(--fg-subtle);
  transition:
    background var(--dur-fast) var(--ease),
    color var(--dur-fast) var(--ease),
    box-shadow var(--dur-fast) var(--ease);
  background: transparent;
}

.p-filter-chip:hover {
  color: var(--fg);
}

.p-filter-chip--pill {
  padding: 4px 10px;
  font-size: 11px;
  border-radius: var(--r-full);
}

.p-filter-chip--pill.is-active {
  color: var(--fg);
  background: var(--surface);
  box-shadow: var(--shadow-1);
}

.p-filter-chip--flat {
  padding: 3px 8px;
  font-size: var(--t-xs);
  text-transform: uppercase;
  letter-spacing: var(--tracking-label);
  border-radius: var(--r-1);
}

.p-filter-chip--flat.is-active {
  color: var(--fg);
  background: var(--active);
}
</style>

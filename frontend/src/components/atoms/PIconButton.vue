<script setup lang="ts">
/**
 * Square borderless icon-only button used in panel headers and toolbars.
 *
 * If `tooltip` is provided, wraps in PTooltip for hover label + native title.
 */
import PTooltip from './PTooltip.vue'

interface Props {
  size?: number
  tooltip?: string
  shortcut?: string
  tooltipPosition?: 'top' | 'right' | 'bottom' | 'left'
}

withDefaults(defineProps<Props>(), {
  size: 22,
  tooltipPosition: 'bottom',
})
</script>

<template>
  <PTooltip
    v-if="tooltip"
    :label="tooltip"
    :shortcut="shortcut"
    :position="tooltipPosition"
  >
    <button
      type="button"
      class="p-icon-button"
      :style="{ width: `${size}px`, height: `${size}px` }"
    >
      <slot />
    </button>
  </PTooltip>
  <button
    v-else
    type="button"
    class="p-icon-button"
    :style="{ width: `${size}px`, height: `${size}px` }"
  >
    <slot />
  </button>
</template>

<style scoped>
.p-icon-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  color: var(--fg-subtle);
  border-radius: var(--r-2);
  transition:
    background var(--dur-fast) var(--ease),
    color var(--dur-fast) var(--ease);
}

.p-icon-button:hover {
  background: var(--hover);
  color: var(--fg);
}

.p-icon-button:active {
  transform: scale(0.94);
}
</style>

<script setup lang="ts">
/**
 * Lightweight CSS-only tooltip wrapper.
 *
 * Renders the wrapped child unchanged and shows a small floating label on
 * hover/focus. Position defaults to `right` (best for the icon rail) but can
 * be overridden per-instance.
 *
 * The wrapped element keeps a `title` for screen readers and as a fallback.
 */

interface Props {
  label: string
  position?: 'top' | 'right' | 'bottom' | 'left'
  shortcut?: string
}

withDefaults(defineProps<Props>(), {
  position: 'right',
})
</script>

<template>
  <span class="p-tooltip" :class="`p-tooltip--${position}`" :title="label">
    <slot />
    <span class="p-tooltip__pop" role="tooltip">
      {{ label }}
      <span v-if="shortcut" class="p-tooltip__kbd">{{ shortcut }}</span>
    </span>
  </span>
</template>

<style scoped>
.p-tooltip {
  position: relative;
  display: inline-flex;
}

.p-tooltip__pop {
  position: absolute;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 8px;
  font-size: 11px;
  line-height: 1;
  font-weight: 500;
  color: var(--fg);
  background: var(--surface-2);
  border: 1px solid var(--line-strong);
  border-radius: var(--r-1);
  white-space: nowrap;
  box-shadow: var(--shadow-2);
  opacity: 0;
  pointer-events: none;
  transform: translateY(0);
  transition:
    opacity var(--dur-fast) var(--ease),
    transform var(--dur-fast) var(--ease);
  z-index: 50;
}

.p-tooltip__kbd {
  font-family: var(--font-mono);
  font-size: 10px;
  color: var(--fg-subtle);
  padding: 1px 4px;
  border: 1px solid var(--line-strong);
  border-radius: 3px;
}

.p-tooltip:hover .p-tooltip__pop,
.p-tooltip:focus-within .p-tooltip__pop {
  opacity: 1;
  transition-delay: 200ms;
}

.p-tooltip--right .p-tooltip__pop {
  left: calc(100% + 8px);
  top: 50%;
  transform: translateY(-50%);
}

.p-tooltip--left .p-tooltip__pop {
  right: calc(100% + 8px);
  top: 50%;
  transform: translateY(-50%);
}

.p-tooltip--top .p-tooltip__pop {
  bottom: calc(100% + 6px);
  left: 50%;
  transform: translateX(-50%);
}

.p-tooltip--bottom .p-tooltip__pop {
  top: calc(100% + 6px);
  left: 50%;
  transform: translateX(-50%);
}
</style>

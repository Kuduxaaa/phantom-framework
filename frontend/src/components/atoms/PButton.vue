<script setup lang="ts">
/**
 * Buttons across all surfaces.
 *
 * Variants:
 *   - primary   → high-contrast (foreground on background)
 *   - accent    → vermillion brand action
 *   - secondary → outlined surface button
 *   - ghost     → transparent, hover-tinted
 */

interface Props {
  variant?: 'primary' | 'accent' | 'secondary' | 'ghost'
  size?: 'sm' | 'md'
  active?: boolean
  type?: 'button' | 'submit' | 'reset'
  disabled?: boolean
}

withDefaults(defineProps<Props>(), {
  variant: 'ghost',
  size: 'sm',
  type: 'button',
})
</script>

<template>
  <button
    :type="type"
    :disabled="disabled"
    class="p-button"
    :class="[`p-button--${variant}`, `p-button--${size}`, { 'is-active': active }]"
  >
    <slot name="icon" />
    <slot />
  </button>
</template>

<style scoped>
.p-button {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: var(--t-sm);
  font-weight: 500;
  border-radius: var(--r-2);
  border: 1px solid transparent;
  white-space: nowrap;
  transition:
    background var(--dur-fast) var(--ease),
    color var(--dur-fast) var(--ease),
    border-color var(--dur-fast) var(--ease);
}

.p-button--sm {
  height: 26px;
  padding: 0 10px;
}

.p-button--md {
  height: 32px;
  padding: 0 14px;
}

.p-button--primary {
  background: var(--fg);
  color: var(--bg);
  border-color: var(--fg);
}

.p-button--accent {
  background: var(--accent);
  color: var(--accent-text);
  border-color: var(--accent);
}

.p-button--accent:hover {
  background: var(--accent-hover);
  border-color: var(--accent-hover);
}

.p-button--secondary {
  background: var(--surface);
  color: var(--fg);
  border-color: var(--line-strong);
}

.p-button--secondary:hover {
  border-color: var(--fg-subtle);
}

.p-button--ghost {
  color: var(--fg-muted);
}

.p-button--ghost:hover,
.p-button--ghost.is-active {
  background: var(--hover);
  color: var(--fg);
}

.p-button--ghost.is-active {
  background: var(--active);
}

.p-button:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}
</style>

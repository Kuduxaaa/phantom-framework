<script setup lang="ts">
/**
 * Bottom status strip — monospace, sparse, calm.
 *
 * Use the default slot for `<PStatusItem>` children.
 */
</script>

<template>
  <footer class="p-status-bar">
    <slot />
  </footer>
</template>

<style scoped>
.p-status-bar {
  display: flex;
  align-items: center;
  gap: 16px;
  height: 24px;
  padding: 0 14px;
  background: transparent;
  font-size: 11px;
  color: var(--fg-subtle);
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
  flex-shrink: 0;
}
</style>

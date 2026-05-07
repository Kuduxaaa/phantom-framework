<script setup lang="ts">
/**
 * Keyboard-key indicator. Use for hints in palettes, tooltips, footers.
 */
</script>

<template>
  <kbd class="p-kbd">
    <slot />
  </kbd>
</template>

<style scoped>
.p-kbd {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 18px;
  height: 18px;
  padding: 0 4px;
  font-family: var(--font-mono);
  font-size: 10px;
  color: var(--fg-muted);
  background: var(--surface);
  border: 1px solid var(--line-strong);
  border-radius: var(--r-1);
  box-shadow: inset 0 -1px 0 var(--line-strong);
}
</style>

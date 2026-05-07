<script setup lang="ts">
/**
 * Single item inside the bottom status bar.
 */

interface Props {
  color?: string
}

defineProps<Props>()
</script>

<template>
  <span class="p-status-item" :style="{ color: color || 'var(--fg-subtle)' }">
    <slot name="icon" />
    <slot />
  </span>
</template>

<style scoped>
.p-status-item {
  display: inline-flex;
  align-items: center;
  gap: 5px;
}
</style>

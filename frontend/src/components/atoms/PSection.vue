<script setup lang="ts">
/**
 * Labeled content section with optional right-aligned action slot.
 *
 * Used to group related content under an uppercase title.
 */

interface Props {
  title: string
}

defineProps<Props>()
</script>

<template>
  <section class="p-section">
    <header class="p-section__header">
      <span class="label">{{ title }}</span>
      <slot name="action" />
    </header>
    <slot />
  </section>
</template>

<style scoped>
.p-section__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 12px;
}
</style>

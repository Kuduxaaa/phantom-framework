<script setup lang="ts">
/**
 * Floating-card container for a view's primary content area.
 *
 * Provides the card chrome (radius, shadow, surface) so individual views
 * don't repeat layout boilerplate.
 */
</script>

<template>
  <main class="p-main-panel">
    <slot />
  </main>
</template>

<style scoped>
.p-main-panel {
  flex: 1;
  display: flex;
  flex-direction: column;
  background: var(--surface);
  min-width: 0;
  min-height: 0;
  border-radius: var(--r-3);
  box-shadow: var(--shadow-2);
  overflow: hidden;
  margin: 6px 0 0 0;
  animation: phFadeIn var(--dur-slow) var(--ease-out);
}
</style>

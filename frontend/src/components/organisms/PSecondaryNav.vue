<script setup lang="ts">
/**
 * Contextual list panel — sits between the icon rail and the main content.
 *
 * Used for vault lists, target lists, signature catalogs, scan history, etc.
 * Header receives an `action` slot (typically a "+" icon button); footer is
 * for compact summary text.
 */

interface Props {
  title: string
  footer?: string
}

defineProps<Props>()
</script>

<template>
  <aside class="p-secondary-nav">
    <header class="p-secondary-nav__header">
      <span class="label">{{ title }}</span>
      <slot name="action" />
    </header>
    <div class="p-secondary-nav__body">
      <slot />
    </div>
    <footer v-if="footer" class="p-secondary-nav__footer">{{ footer }}</footer>
  </aside>
</template>

<style scoped>
.p-secondary-nav {
  width: 252px;
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  background: transparent;
  min-height: 0;
}

.p-secondary-nav__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 12px 8px;
  flex-shrink: 0;
}

.p-secondary-nav__body {
  flex: 1;
  overflow-y: auto;
  padding: 0 6px 6px;
}

.p-secondary-nav__footer {
  padding: 8px 12px;
  border-top: 1px solid var(--line);
  font-size: var(--t-xs);
  color: var(--fg-subtle);
  flex-shrink: 0;
}
</style>

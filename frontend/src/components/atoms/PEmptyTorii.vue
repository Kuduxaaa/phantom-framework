<script setup lang="ts">
/**
 * Empty-state placeholder. The Torii silhouette is intentionally faint —
 * this is the only place the brand mark appears as decoration rather than a logo.
 *
 * Optional `action` slot for a primary call-to-action below the hint copy.
 */

interface Props {
  title: string
  hint?: string
}

defineProps<Props>()
</script>

<template>
  <div class="p-empty-torii">
    <svg
      width="56"
      height="56"
      viewBox="0 0 64 64"
      fill="none"
      stroke="var(--line-strong)"
      stroke-width="1.5"
      stroke-linecap="square"
      aria-hidden="true"
    >
      <path d="M6 16h52" />
      <path d="M10 23h44" />
      <path d="M16 23v33" />
      <path d="M48 23v33" />
      <path d="M14 34h36" />
    </svg>
    <div class="p-empty-torii__copy">
      <div class="p-empty-torii__title">{{ title }}</div>
      <div v-if="hint" class="p-empty-torii__hint">{{ hint }}</div>
    </div>
    <div v-if="$slots.action" class="p-empty-torii__action">
      <slot name="action" />
    </div>
  </div>
</template>

<style scoped>
.p-empty-torii {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: var(--s-12) var(--s-8);
  color: var(--fg-muted);
  text-align: center;
  gap: var(--s-6);
  flex: 1;
  min-height: 280px;
}

.p-empty-torii__title {
  font-size: var(--t-md);
  color: var(--fg);
  font-weight: 500;
  margin-bottom: 4px;
}

.p-empty-torii__hint {
  font-size: var(--t-sm);
  color: var(--fg-subtle);
  max-width: 380px;
}

.p-empty-torii__action {
  margin-top: var(--s-3);
}
</style>

<script setup lang="ts">
/**
 * Mono-spaced code block for short snippets (URLs, commands, JSON fragments).
 *
 * Use `multiline` for blocks that should preserve linebreaks and breathing room.
 */

interface Props {
  multiline?: boolean
}

withDefaults(defineProps<Props>(), {
  multiline: false,
})
</script>

<template>
  <pre class="p-code-block" :class="{ 'is-multiline': multiline }"><slot /></pre>
</template>

<style scoped>
.p-code-block {
  margin: 0;
  padding: 4px 8px;
  font-family: var(--font-mono);
  font-size: 11px;
  line-height: 1.6;
  color: var(--fg);
  background: var(--bg-sunken);
  border: 1px solid var(--line);
  border-radius: var(--r-2);
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-all;
}

.p-code-block.is-multiline {
  padding: 10px 12px;
}
</style>

<script setup lang="ts">
/**
 * Multi-line text input — two-way bound, optionally mono.
 */

interface Props {
  modelValue: string
  placeholder?: string
  rows?: number
  mono?: boolean
  disabled?: boolean
}

withDefaults(defineProps<Props>(), {
  rows: 4,
  mono: false,
})

defineEmits<{ 'update:modelValue': [value: string] }>()
</script>

<template>
  <textarea
    :value="modelValue"
    :placeholder="placeholder"
    :rows="rows"
    :disabled="disabled"
    class="p-textarea"
    :class="{ 'is-mono': mono }"
    @input="$emit('update:modelValue', ($event.target as HTMLTextAreaElement).value)"
  />
</template>

<style scoped>
.p-textarea {
  width: 100%;
  resize: vertical;
  min-height: 60px;
  background: var(--bg-sunken);
  color: var(--fg);
  border: 1px solid var(--line-strong);
  border-radius: var(--r-2);
  padding: 8px 10px;
  font-size: var(--t-md);
  line-height: 1.55;
  outline: none;
  transition:
    border-color var(--dur-fast) var(--ease),
    box-shadow var(--dur-fast) var(--ease);
}

.p-textarea.is-mono {
  font-family: var(--font-mono);
  font-size: var(--t-sm);
  line-height: 1.7;
}

.p-textarea::placeholder {
  color: var(--fg-faint);
}

.p-textarea:hover {
  border-color: var(--fg-faint);
}

.p-textarea:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-soft);
}

.p-textarea:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
</style>

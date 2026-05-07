<script setup lang="ts">
/**
 * Text input — two-way bound via `v-model`. Supports `mono` for code-style.
 */

interface Props {
  modelValue: string
  placeholder?: string
  type?: 'text' | 'url' | 'email' | 'number' | 'password'
  mono?: boolean
  size?: 'sm' | 'md'
  autofocus?: boolean
  disabled?: boolean
}

withDefaults(defineProps<Props>(), {
  type: 'text',
  mono: false,
  size: 'md',
})

defineEmits<{ 'update:modelValue': [value: string] }>()
</script>

<template>
  <input
    :type="type"
    :value="modelValue"
    :placeholder="placeholder"
    :autofocus="autofocus"
    :disabled="disabled"
    class="p-input"
    :class="[`p-input--${size}`, { 'is-mono': mono }]"
    @input="$emit('update:modelValue', ($event.target as HTMLInputElement).value)"
  />
</template>

<style scoped>
.p-input {
  width: 100%;
  background: var(--bg-sunken);
  color: var(--fg);
  border: 1px solid var(--line-strong);
  border-radius: var(--r-2);
  padding: 0 10px;
  font-size: var(--t-md);
  outline: none;
  transition:
    border-color var(--dur-fast) var(--ease),
    box-shadow var(--dur-fast) var(--ease);
}

.p-input--sm {
  height: 28px;
  font-size: var(--t-sm);
}

.p-input--md {
  height: 34px;
}

.p-input.is-mono {
  font-family: var(--font-mono);
}

.p-input::placeholder {
  color: var(--fg-faint);
}

.p-input:hover {
  border-color: var(--fg-faint);
}

.p-input:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-soft);
}

.p-input:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
</style>

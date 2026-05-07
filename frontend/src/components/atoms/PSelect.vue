<script setup lang="ts">
/**
 * Native `<select>` styled to match the Phantom design system.
 *
 * Two-way bound; options are `{ value, label }` pairs.
 */
import PIcon from './PIcon.vue'

export interface SelectOption {
  value: string
  label: string
}

interface Props {
  modelValue: string
  options: SelectOption[]
  size?: 'sm' | 'md'
  disabled?: boolean
}

withDefaults(defineProps<Props>(), {
  size: 'md',
})

defineEmits<{ 'update:modelValue': [value: string] }>()
</script>

<template>
  <span class="p-select" :class="`p-select--${size}`">
    <select
      :value="modelValue"
      :disabled="disabled"
      class="p-select__field"
      @change="$emit('update:modelValue', ($event.target as HTMLSelectElement).value)"
    >
      <option v-for="opt in options" :key="opt.value" :value="opt.value">{{ opt.label }}</option>
    </select>
    <PIcon name="chevron-down" :size="11" class="p-select__icon" />
  </span>
</template>

<style scoped>
.p-select {
  position: relative;
  display: inline-flex;
  align-items: center;
}

.p-select__field {
  appearance: none;
  width: 100%;
  background: var(--bg-sunken);
  color: var(--fg);
  border: 1px solid var(--line-strong);
  border-radius: var(--r-2);
  padding: 0 28px 0 10px;
  font-size: var(--t-md);
  outline: none;
  cursor: pointer;
  transition:
    border-color var(--dur-fast) var(--ease),
    box-shadow var(--dur-fast) var(--ease);
}

.p-select--sm .p-select__field {
  height: 28px;
  font-size: var(--t-sm);
  padding-right: 24px;
}

.p-select--md .p-select__field {
  height: 34px;
}

.p-select__field:hover {
  border-color: var(--fg-faint);
}

.p-select__field:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-soft);
}

.p-select__icon {
  position: absolute;
  right: 8px;
  color: var(--fg-subtle);
  pointer-events: none;
}
</style>

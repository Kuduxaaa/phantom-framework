<script setup lang="ts">
/**
 * Compact filter-style text input with leading search icon.
 *
 * Two-way bound via `v-model`. Use for inline filtering — for the global
 * command palette use the dedicated palette component.
 */
import PIcon from './PIcon.vue'

interface Props {
  modelValue: string
  placeholder?: string
}

defineProps<Props>()

defineEmits<{ 'update:modelValue': [value: string] }>()
</script>

<template>
  <div class="p-search-input">
    <PIcon name="search" :size="11" class="p-search-input__icon" />
    <input
      :value="modelValue"
      :placeholder="placeholder"
      type="text"
      class="p-search-input__field"
      @input="$emit('update:modelValue', ($event.target as HTMLInputElement).value)"
    />
  </div>
</template>

<style scoped>
.p-search-input {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 0 8px;
  height: 26px;
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: var(--r-2);
}

.p-search-input__icon {
  color: var(--fg-faint);
}

.p-search-input__field {
  flex: 1;
  border: 0;
  background: transparent;
  outline: none;
  font-size: var(--t-sm);
  color: var(--fg);
  min-width: 0;
}

.p-search-input__field::placeholder {
  color: var(--fg-faint);
}
</style>

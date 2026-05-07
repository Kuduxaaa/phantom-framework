<script setup lang="ts">
/**
 * Two-state toggle (on/off). Two-way bound via `v-model`.
 */

interface Props {
  modelValue: boolean
  disabled?: boolean
}

defineProps<Props>()

const emit = defineEmits<{ 'update:modelValue': [value: boolean] }>()

function toggle(): void {
  emit('update:modelValue', !arguments)
}
</script>

<template>
  <button
    type="button"
    role="switch"
    :aria-checked="modelValue"
    :disabled="disabled"
    class="p-toggle"
    :class="{ 'is-on': modelValue }"
    @click="$emit('update:modelValue', !modelValue)"
  >
    <span class="p-toggle__knob" />
  </button>
</template>

<style scoped>
.p-toggle {
  width: 30px;
  height: 18px;
  border-radius: 9px;
  padding: 2px;
  background: var(--line-strong);
  display: inline-flex;
  align-items: center;
  justify-content: flex-start;
  transition: background var(--dur-fast) var(--ease);
}

.p-toggle.is-on {
  background: var(--accent);
  justify-content: flex-end;
}

.p-toggle__knob {
  width: 14px;
  height: 14px;
  border-radius: 50%;
  background: var(--surface);
  transition: transform var(--dur-fast) var(--ease);
}

.p-toggle:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}
</style>

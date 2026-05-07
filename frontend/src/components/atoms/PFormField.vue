<script setup lang="ts">
/**
 * Form field wrapper — label, optional hint, and the bound input as a slot.
 *
 * Use inside modal bodies and editor cards for consistent label/spacing rhythm.
 */

interface Props {
  label: string
  hint?: string
  required?: boolean
}

defineProps<Props>()
</script>

<template>
  <div class="p-form-field">
    <div class="p-form-field__label-row">
      <span class="p-form-field__label">
        {{ label }}<span v-if="required" class="p-form-field__required">*</span>
      </span>
      <span v-if="$slots.action" class="p-form-field__action">
        <slot name="action" />
      </span>
    </div>
    <slot />
    <span v-if="hint" class="p-form-field__hint">{{ hint }}</span>
  </div>
</template>

<style scoped>
.p-form-field {
  display: grid;
  gap: 6px;
}

.p-form-field__label-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.p-form-field__label {
  font-size: var(--t-sm);
  font-weight: 500;
  color: var(--fg);
}

.p-form-field__required {
  color: var(--accent);
  margin-left: 2px;
}

.p-form-field__hint {
  font-size: var(--t-xs);
  color: var(--fg-subtle);
  line-height: 1.5;
}
</style>

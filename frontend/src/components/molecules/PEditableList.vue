<script setup lang="ts">
/**
 * Editable list of mono-spaced strings — payloads, regex patterns, words.
 *
 * Renders existing rows with a remove (×) button and a row-style "+ Add"
 * input that commits on Enter. Two-way bound via `v-model` (string array).
 */
import { ref } from 'vue'
import PIcon from '../atoms/PIcon.vue'

interface Props {
  modelValue: string[]
  addLabel?: string
  placeholder?: string
  /**
   * Visual treatment of values: `regex` wraps in /…/, `word` wraps in "…".
   * `plain` shows the raw value.
   */
  kind?: 'plain' | 'regex' | 'word'
}

const props = withDefaults(defineProps<Props>(), {
  addLabel: 'Add',
  placeholder: 'New value…',
  kind: 'plain',
})

const emit = defineEmits<{ 'update:modelValue': [value: string[]] }>()

const draft = ref<string>('')

function display(value: string): string {
  if (props.kind === 'regex') return `/${value}/`
  if (props.kind === 'word') return `"${value}"`
  return value
}

function commit(): void {
  const v = draft.value.trim()
  if (!v) return
  emit('update:modelValue', [...props.modelValue, v])
  draft.value = ''
}

function remove(idx: number): void {
  emit('update:modelValue', props.modelValue.filter((_, i) => i !== idx))
}
</script>

<template>
  <div class="p-editable-list">
    <div v-for="(item, i) in modelValue" :key="i" class="p-editable-list__row">
      <span class="p-editable-list__idx">{{ i + 1 }}</span>
      <span
        class="p-editable-list__val"
        :class="{ 'is-regex': kind === 'regex', 'is-word': kind === 'word' }"
      >{{ display(item) }}</span>
      <button
        type="button"
        class="p-editable-list__x"
        :title="`Remove ${addLabel.toLowerCase()}`"
        @click="remove(i)"
      >
        <PIcon name="close" :size="11" />
      </button>
    </div>

    <form class="p-editable-list__add" @submit.prevent="commit">
      <PIcon name="plus" :size="11" class="p-editable-list__add-icon" />
      <input
        v-model="draft"
        type="text"
        :placeholder="placeholder"
        class="p-editable-list__add-input"
      />
      <button
        type="submit"
        class="p-editable-list__add-btn"
        :disabled="!draft.trim()"
      >Add</button>
    </form>
  </div>
</template>

<style scoped>
.p-editable-list {
  display: grid;
  gap: 4px;
}

.p-editable-list__row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 10px;
  background: var(--bg-sunken);
  border: 1px solid var(--line-soft);
  border-radius: var(--r-1);
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--fg);
  transition: border-color var(--dur-fast) var(--ease);
}

.p-editable-list__row:hover {
  border-color: var(--line-strong);
}

.p-editable-list__idx {
  color: var(--fg-faint);
  width: 14px;
  text-align: right;
  flex-shrink: 0;
}

.p-editable-list__val {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.p-editable-list__val.is-word {
  color: var(--ok);
}

.p-editable-list__val.is-regex {
  color: var(--accent);
}

.p-editable-list__x {
  color: var(--fg-subtle);
  display: inline-flex;
  align-items: center;
  border-radius: var(--r-1);
  padding: 2px;
  transition: color var(--dur-fast) var(--ease);
}

.p-editable-list__x:hover {
  color: var(--err);
}

.p-editable-list__add {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 10px;
  background: transparent;
  border: 1px dashed var(--line);
  border-radius: var(--r-1);
  transition:
    border-color var(--dur-fast) var(--ease),
    background var(--dur-fast) var(--ease);
}

.p-editable-list__add:focus-within {
  border-color: var(--accent);
  border-style: solid;
  background: var(--bg-sunken);
}

.p-editable-list__add-icon {
  color: var(--fg-faint);
  flex-shrink: 0;
}

.p-editable-list__add-input {
  flex: 1;
  background: transparent;
  border: 0;
  outline: none;
  color: var(--fg);
  font-family: var(--font-mono);
  font-size: 11px;
}

.p-editable-list__add-input::placeholder {
  color: var(--fg-faint);
}

.p-editable-list__add-btn {
  font-size: 10.5px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: var(--tracking-label);
  color: var(--accent);
  padding: 2px 6px;
  border-radius: var(--r-1);
}

.p-editable-list__add-btn:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.p-editable-list__add-btn:not(:disabled):hover {
  background: var(--accent-soft);
}
</style>

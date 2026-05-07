<script setup lang="ts">
/**
 * Sidebar list row — leading slot (icon/glyph), label + optional sub line, trailing slot.
 *
 * Selection state is purely visual; routing/selection logic lives in the parent.
 */

interface Props {
  active?: boolean
  label: string
  sub?: string
}

withDefaults(defineProps<Props>(), {
  active: false,
})

defineEmits<{ click: [] }>()
</script>

<template>
  <button
    type="button"
    class="p-nav-row"
    :class="{ 'is-active': active }"
    @click="$emit('click')"
  >
    <span v-if="$slots.leading" class="p-nav-row__leading">
      <slot name="leading" />
    </span>
    <span class="p-nav-row__body">
      <span class="p-nav-row__label">{{ label }}</span>
      <span v-if="sub" class="p-nav-row__sub">{{ sub }}</span>
    </span>
    <span v-if="$slots.trailing" class="p-nav-row__trailing">
      <slot name="trailing" />
    </span>
  </button>
</template>

<style scoped>
.p-nav-row {
  position: relative;
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  padding: 6px 8px;
  min-height: 30px;
  border-radius: var(--r-2);
  background: transparent;
  color: var(--fg);
  text-align: left;
  transition:
    background var(--dur-fast) var(--ease),
    color var(--dur-fast) var(--ease);
}

.p-nav-row:hover {
  background: var(--hover);
}

.p-nav-row.is-active {
  background: var(--selected);
}

.p-nav-row.is-active::before {
  content: '';
  position: absolute;
  left: -2px;
  top: 8px;
  bottom: 8px;
  width: 2px;
  border-radius: 2px;
  background: var(--accent);
}

.p-nav-row.is-active:hover {
  background: var(--selected);
}

.p-nav-row__leading {
  flex-shrink: 0;
  color: var(--fg-muted);
  display: inline-flex;
}

.p-nav-row__body {
  flex: 1;
  min-width: 0;
}

.p-nav-row__label {
  display: block;
  font-size: var(--t-sm);
  font-weight: 500;
  color: var(--fg);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.p-nav-row__sub {
  display: block;
  font-size: var(--t-xs);
  color: var(--fg-subtle);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.p-nav-row__trailing {
  flex-shrink: 0;
  color: var(--fg-subtle);
  font-size: var(--t-xs);
}
</style>

<script setup lang="ts">
/**
 * Recursive asset hierarchy tree.
 *
 * Self-references for nested levels via `<PAssetTree>` import. Each row
 * toggles open/closed; root entries default to open.
 */
import { ref } from 'vue'
import PIcon from '../atoms/PIcon.vue'

export interface AssetNode {
  type: string
  label: string
  sensitive?: boolean
  children?: AssetNode[]
}

interface Props {
  nodes: AssetNode[]
  depth?: number
}

const props = withDefaults(defineProps<Props>(), {
  depth: 0,
})

const closed = ref<Set<string>>(new Set())

function key(idx: number): string {
  return `${props.depth}:${idx}`
}

function toggle(idx: number): void {
  const k = key(idx)
  if (closed.value.has(k)) closed.value.delete(k)
  else closed.value.add(k)
}

function isOpen(idx: number): boolean {
  return !closed.value.has(key(idx))
}
</script>

<template>
  <div class="p-asset-tree">
    <template v-for="(node, idx) in nodes" :key="idx">
      <div
        class="p-asset-tree__row"
        :style="{ paddingLeft: `${depth * 18}px`, cursor: node.children?.length ? 'pointer' : 'default' }"
        @click="node.children?.length && toggle(idx)"
      >
        <span class="p-asset-tree__chevron">
          <PIcon
            v-if="node.children?.length"
            :name="isOpen(idx) ? 'chevron-down' : 'chevron-right'"
            :size="11"
          />
        </span>
        <span class="p-asset-tree__type">{{ node.type.toLowerCase().replace('_', ' ') }}</span>
        <span class="p-asset-tree__label" :class="{ 'is-sensitive': node.sensitive }">{{ node.label }}</span>
        <PIcon v-if="node.sensitive" name="lock" :size="10" class="p-asset-tree__lock" />
      </div>
      <PAssetTree
        v-if="node.children?.length && isOpen(idx)"
        :nodes="node.children"
        :depth="depth + 1"
      />
    </template>
  </div>
</template>

<script lang="ts">
export default { name: 'PAssetTree' }
</script>

<style scoped>
.p-asset-tree {
  font-family: var(--font-mono);
  font-size: 12px;
}

.p-asset-tree__row {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 3px 0;
  border-radius: var(--r-1);
}

.p-asset-tree__row:hover {
  background: var(--hover);
}

.p-asset-tree__chevron {
  width: 12px;
  color: var(--fg-faint);
  display: inline-flex;
}

.p-asset-tree__type {
  font-size: 9px;
  text-transform: uppercase;
  letter-spacing: var(--tracking-label);
  color: var(--fg-faint);
  min-width: 70px;
}

.p-asset-tree__label.is-sensitive {
  color: var(--sev-high);
}

.p-asset-tree__lock {
  color: var(--sev-high);
}
</style>

<script setup lang="ts">
/**
 * Top application title bar — torii mark, app name, current vault breadcrumb,
 * and the global search/command-palette opener.
 */
import { computed } from 'vue'
import PToriiMark from '../atoms/PToriiMark.vue'
import PIcon from '../atoms/PIcon.vue'
import PKbd from '../atoms/PKbd.vue'
import { useUiStore } from '@/stores/ui'
import { useVaultsStore } from '@/stores/vaults'

const ui = useUiStore()
const vaults = useVaultsStore()

const activeVault = computed(() => vaults.active)
</script>

<template>
  <div class="p-title-bar">
    <div class="p-title-bar__brand">
      <PToriiMark :size="18" />
      <span class="p-title-bar__app">Phantom</span>
      <span class="p-title-bar__sep">/</span>
      <span class="p-title-bar__vault">{{ activeVault?.name ?? 'No vault' }}</span>
      <span v-if="activeVault" class="p-title-bar__platform">{{ activeVault.platform }}</span>
    </div>

    <span class="p-title-bar__spacer" />

    <button type="button" class="p-title-bar__palette" @click="ui.openPalette()">
      <PIcon name="search" :size="13" />
      <span class="p-title-bar__palette-text">Search or run command</span>
      <PKbd>⌘K</PKbd>
    </button>
  </div>
</template>

<style scoped>
.p-title-bar {
  display: flex;
  align-items: center;
  height: 48px;
  padding: 0 16px;
  background: var(--bg);
  gap: 14px;
  flex-shrink: 0;
}

.p-title-bar__brand {
  display: flex;
  align-items: center;
  gap: 10px;
  color: var(--fg);
}

.p-title-bar__app {
  font-family: var(--font-display);
  font-size: 14px;
  font-weight: 600;
  letter-spacing: -0.01em;
}

.p-title-bar__sep {
  color: var(--fg-faint);
  font-size: 13px;
  margin: 0 2px;
}

.p-title-bar__vault {
  font-size: 13px;
  color: var(--fg-muted);
  font-weight: 500;
}

.p-title-bar__platform {
  font-size: 10px;
  color: var(--fg-subtle);
  font-family: var(--font-mono);
  font-weight: 500;
  padding: 2px 7px;
  background: var(--surface);
  border-radius: var(--r-full);
  margin-left: 4px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.p-title-bar__spacer {
  flex: 1;
}

.p-title-bar__palette {
  display: flex;
  align-items: center;
  gap: 8px;
  height: 30px;
  padding: 0 12px;
  min-width: 260px;
  background: var(--surface);
  border: 1px solid transparent;
  border-radius: var(--r-full);
  color: var(--fg-subtle);
  font-size: 12px;
  cursor: pointer;
  box-shadow: var(--shadow-1);
  transition:
    box-shadow var(--dur-fast) var(--ease),
    border-color var(--dur-fast) var(--ease),
    color var(--dur-fast) var(--ease);
}

.p-title-bar__palette:hover {
  box-shadow: var(--shadow-2);
  border-color: var(--line-strong);
  color: var(--fg-muted);
}

.p-title-bar__palette-text {
  flex: 1;
  text-align: left;
}
</style>

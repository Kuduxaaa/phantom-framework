<script setup lang="ts">
/**
 * Top-level application chrome: title bar, primary nav rail, routed view,
 * status bar, and the global command palette.
 *
 * Wires the ⌘K / Ctrl+K shortcut to the UI store, and ESC to close the
 * inspector or palette. Individual views are responsible for their own
 * secondary nav and inspector panes.
 */
import { computed } from 'vue'
import { RouterView } from 'vue-router'
import PTitleBar from '@/components/organisms/PTitleBar.vue'
import PPrimaryNav from '@/components/organisms/PPrimaryNav.vue'
import PCommandPalette from '@/components/organisms/PCommandPalette.vue'
import PStatusBar from '@/components/molecules/PStatusBar.vue'
import PStatusItem from '@/components/molecules/PStatusItem.vue'
import PKbd from '@/components/atoms/PKbd.vue'
import { useFindingsStore } from '@/stores/findings'
import { useUiStore } from '@/stores/ui'
import { useVaultsStore } from '@/stores/vaults'
import { useKeybinding } from '@/composables/useKeybinding'

const ui = useUiStore()
const vaults = useVaultsStore()
const findings = useFindingsStore()

useKeybinding(
  'k',
  (event) => {
    event.preventDefault()
    ui.togglePalette()
  },
  { metaOrCtrl: true },
)

useKeybinding('Escape', () => {
  if (ui.paletteOpen) {
    ui.closePalette()
    return
  }
  if (findings.inspectedId !== null) findings.inspect(null)
})

const findingsTotal = computed<number>(() => findings.items.length)
const activeVaultId = computed<number | undefined>(() => vaults.active?.id)
</script>

<template>
  <div class="p-app">
    <PTitleBar />

    <div class="p-app__body">
      <PPrimaryNav />
      <RouterView />
    </div>

    <PStatusBar>
      <PStatusItem>
        <template #icon>
          <span class="p-app__ok-dot" />
        </template>
        ready
      </PStatusItem>
      <PStatusItem>vault {{ activeVaultId }}</PStatusItem>
      <PStatusItem>{{ findingsTotal }} findings</PStatusItem>
      <PStatusItem>2 scans queued</PStatusItem>
      <span class="p-app__spacer" />
      <span class="p-app__hint">
        <PKbd>⌘</PKbd><PKbd>K</PKbd>
        <span class="p-app__hint-label">command palette</span>
      </span>
      <PStatusItem>phantom 1.0.0-beta</PStatusItem>
    </PStatusBar>

    <PCommandPalette />
  </div>
</template>

<style scoped>
.p-app {
  width: 100%;
  height: 100%;
  display: flex;
  flex-direction: column;
  background: var(--bg);
  color: var(--fg);
  font-family: var(--font-sans);
  font-size: var(--t-md);
  overflow: hidden;
}

.p-app__body {
  flex: 1;
  display: flex;
  min-height: 0;
  overflow: hidden;
  padding: 0 8px 8px 4px;
  gap: 0;
}

.p-app__ok-dot {
  width: 6px;
  height: 6px;
  border-radius: 999px;
  background: var(--ok);
}

.p-app__spacer {
  flex: 1;
}

.p-app__hint {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 11px;
  color: var(--fg-faint);
  font-family: var(--font-mono);
}

.p-app__hint-label {
  margin-left: 4px;
}
</style>

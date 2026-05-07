<script setup lang="ts">
/**
 * ⌘K command palette — global, secondary-by-design.
 *
 * Search-as-you-type filtering across navigation, actions, settings, and
 * jump-to entries. Closes on backdrop click, Escape, or after running an action.
 */
import { computed, nextTick, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import PIcon from '../atoms/PIcon.vue'
import PKbd from '../atoms/PKbd.vue'
import type { IconName } from '../icons/icon-paths'
import { useUiStore } from '@/stores/ui'

interface Command {
  id: string
  group: 'Navigate' | 'Actions' | 'Settings' | 'Jump to'
  label: string
  icon: IconName
  kbd?: string
  sub?: string
  run?: () => void
}

const ui = useUiStore()
const router = useRouter()
const query = ref<string>('')
const inputRef = ref<HTMLInputElement | null>(null)

watch(
  () => ui.paletteOpen,
  (open) => {
    if (!open) return
    query.value = ''
    void nextTick(() => inputRef.value?.focus())
  },
)

function nav(path: string): () => void {
  return () => {
    void router.push(path)
    ui.closePalette()
  }
}

const commands = computed<Command[]>(() => [
  { id: 'go-vaults', group: 'Navigate', label: 'Go to Vaults', kbd: 'G V', icon: 'vault', run: nav('/') },
  { id: 'go-targets', group: 'Navigate', label: 'Go to Targets', kbd: 'G T', icon: 'target', run: nav('/targets') },
  { id: 'go-findings', group: 'Navigate', label: 'Go to Findings', kbd: 'G F', icon: 'bug', run: nav('/findings') },
  { id: 'go-scans', group: 'Navigate', label: 'Go to Scans', kbd: 'G S', icon: 'scan', run: nav('/scans') },
  { id: 'go-sigs', group: 'Navigate', label: 'Go to Signatures', kbd: 'G I', icon: 'signature', run: nav('/signatures') },
  { id: 'go-proxy', group: 'Navigate', label: 'Go to Proxy', kbd: 'G P', icon: 'proxy', run: nav('/proxy') },

  { id: 'new-scan', group: 'Actions', label: 'Run new scan…', icon: 'play', run: nav('/scans') },
  { id: 'new-target', group: 'Actions', label: 'Add new target…', icon: 'plus', run: nav('/targets') },
  { id: 'new-sig', group: 'Actions', label: 'Create new signature…', icon: 'plus', run: nav('/signatures') },
  { id: 'proxy-toggle', group: 'Actions', label: 'Toggle proxy capture', icon: 'pause', run: nav('/proxy') },

  { id: 'settings', group: 'Settings', label: 'Open settings', icon: 'settings', run: () => ui.closePalette() },
  { id: 'docs', group: 'Settings', label: 'Open documentation', icon: 'external', run: () => ui.closePalette() },

  { id: 'jump-acme', group: 'Jump to', label: 'api.acme.io', sub: 'target · 5 findings', icon: 'target', run: nav('/targets') },
  { id: 'jump-sqli', group: 'Jump to', label: 'sql-injection-error-based', sub: 'signature · v1.4', icon: 'signature', run: nav('/signatures') },
  { id: 'jump-jwt', group: 'Jump to', label: 'JWT accepts "none" algorithm', sub: 'finding · critical', icon: 'bug', run: nav('/findings') },
])

const matches = computed<Command[]>(() => {
  const q = query.value.toLowerCase()
  if (!q) return commands.value
  return commands.value.filter((c) =>
    `${c.label} ${c.group} ${c.sub ?? ''}`.toLowerCase().includes(q),
  )
})

const grouped = computed<Record<string, Command[]>>(() => {
  const acc: Record<string, Command[]> = {}
  for (const c of matches.value) (acc[c.group] ??= []).push(c)
  return acc
})

function onKeydown(event: KeyboardEvent): void {
  if (event.key === 'Escape') ui.closePalette()
}
</script>

<template>
  <Teleport to="body">
    <Transition name="p-palette">
      <div v-if="ui.paletteOpen" class="p-palette" @click.self="ui.closePalette()">
      <div class="p-palette__panel" @click.stop>
        <div class="p-palette__search">
          <PIcon name="search" :size="14" />
          <input
            ref="inputRef"
            v-model="query"
            class="p-palette__input"
            placeholder="Search or run a command…"
            @keydown="onKeydown"
          />
          <PKbd>esc</PKbd>
        </div>

        <div class="p-palette__results">
          <template v-for="(items, group) in grouped" :key="group">
            <div class="p-palette__group">
              <div class="label p-palette__group-label">{{ group }}</div>
              <button
                v-for="cmd in items"
                :key="cmd.id"
                type="button"
                class="p-palette__row"
                @click="cmd.run?.()"
              >
                <PIcon :name="cmd.icon" :size="14" class="p-palette__row-icon" />
                <span class="p-palette__row-label">{{ cmd.label }}</span>
                <span v-if="cmd.sub" class="p-palette__row-sub">{{ cmd.sub }}</span>
                <span v-if="cmd.kbd" class="p-palette__row-kbds">
                  <PKbd v-for="(k, i) in cmd.kbd.split(' ')" :key="i">{{ k }}</PKbd>
                </span>
              </button>
            </div>
          </template>

          <div v-if="!matches.length" class="p-palette__empty">
            No commands match "{{ query }}"
          </div>
        </div>

        <footer class="p-palette__footer">
          <span class="p-palette__hint"><PKbd>↑</PKbd><PKbd>↓</PKbd> navigate</span>
          <span class="p-palette__hint"><PKbd>↵</PKbd> select</span>
          <span class="p-palette__spacer" />
          <span>{{ matches.length }} results</span>
        </footer>
      </div>
    </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.p-palette {
  position: fixed;
  inset: 0;
  z-index: 100;
  background: rgba(0, 0, 0, 0.18);
  display: flex;
  align-items: flex-start;
  justify-content: center;
  padding-top: min(15vh, 120px);
}

.p-palette__panel {
  width: 580px;
  max-height: 70vh;
  background: var(--bg-elev);
  border: 1px solid var(--line-strong);
  border-radius: var(--r-3);
  overflow: hidden;
  display: flex;
  flex-direction: column;
  box-shadow: var(--shadow-3);
  animation: phPaletteIn var(--dur) var(--ease-out);
}

.p-palette-enter-active,
.p-palette-leave-active {
  transition: opacity var(--dur) var(--ease-out);
}

.p-palette-enter-from,
.p-palette-leave-to {
  opacity: 0;
}

.p-palette__search {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 16px;
  border-bottom: 1px solid var(--line);
  color: var(--fg-subtle);
}

.p-palette__input {
  flex: 1;
  border: 0;
  background: transparent;
  outline: none;
  font-size: 14px;
  color: var(--fg);
}

.p-palette__results {
  overflow-y: auto;
  flex: 1;
  padding: 6px 0;
}

.p-palette__group {
  padding: 6px 0;
}

.p-palette__group-label {
  padding: 4px 16px;
}

.p-palette__row {
  display: flex;
  align-items: center;
  gap: 10px;
  width: 100%;
  padding: 8px 16px;
  color: var(--fg);
  text-align: left;
  background: transparent;
}

.p-palette__row:hover {
  background: var(--hover);
}

.p-palette__row-icon {
  color: var(--fg-muted);
}

.p-palette__row-label {
  flex: 1;
  font-size: var(--t-md);
}

.p-palette__row-sub {
  font-size: var(--t-xs);
  color: var(--fg-subtle);
}

.p-palette__row-kbds {
  display: inline-flex;
  gap: 3px;
}

.p-palette__empty {
  padding: var(--s-9) var(--s-7);
  text-align: center;
  color: var(--fg-subtle);
  font-size: var(--t-sm);
}

.p-palette__footer {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 8px 16px;
  border-top: 1px solid var(--line);
  font-size: var(--t-xs);
  color: var(--fg-subtle);
}

.p-palette__hint {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

.p-palette__spacer {
  flex: 1;
}
</style>

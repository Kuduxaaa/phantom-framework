<script setup lang="ts">
/**
 * Leftmost vertical icon rail — primary view switcher.
 *
 * Active items get an accent rail on the left edge plus the soft accent
 * background. Tooltips show the label + suggested shortcut on hover.
 */
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import PIcon from '../atoms/PIcon.vue'
import PTooltip from '../atoms/PTooltip.vue'
import type { IconName } from '../icons/icon-paths'
import type { ViewKey } from '@/types'

interface NavItem {
  id: ViewKey
  icon: IconName
  label: string
  path: string
  shortcut: string
}

const ITEMS: NavItem[] = [
  { id: 'vaults', icon: 'vault', label: 'Vaults', path: '/', shortcut: 'G V' },
  { id: 'targets', icon: 'target', label: 'Targets', path: '/targets', shortcut: 'G T' },
  { id: 'findings', icon: 'bug', label: 'Findings', path: '/findings', shortcut: 'G F' },
  { id: 'scans', icon: 'scan', label: 'Scans', path: '/scans', shortcut: 'G S' },
  { id: 'signatures', icon: 'signature', label: 'Signatures', path: '/signatures', shortcut: 'G I' },
  { id: 'proxy', icon: 'proxy', label: 'Proxy', path: '/proxy', shortcut: 'G P' },
  { id: 'workflows', icon: 'workflow', label: 'Workflows', path: '/workflows', shortcut: 'G W' },
  { id: 'notes', icon: 'note', label: 'Notes', path: '/notes', shortcut: 'G N' },
]

const route = useRoute()
const router = useRouter()

const activeId = computed<string>(() => {
  const seg = route.path.split('/')[1] ?? ''
  return seg === '' ? 'vaults' : seg
})

function go(item: NavItem): void {
  void router.push(item.path)
}
</script>

<template>
  <nav class="p-primary-nav" aria-label="Primary navigation">
    <PTooltip
      v-for="item in ITEMS"
      :key="item.id"
      :label="item.label"
      :shortcut="item.shortcut"
      position="right"
    >
      <button
        type="button"
        class="p-primary-nav__item"
        :class="{ 'is-active': activeId === item.id }"
        :aria-current="activeId === item.id ? 'page' : undefined"
        @click="go(item)"
      >
        <PIcon :name="item.icon" :size="17" />
      </button>
    </PTooltip>
    <span class="p-primary-nav__spacer" />
    <PTooltip label="Settings" shortcut=", " position="right">
      <button type="button" class="p-primary-nav__item">
        <PIcon name="settings" :size="16" />
      </button>
    </PTooltip>
  </nav>
</template>

<style scoped>
.p-primary-nav {
  width: 52px;
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
  padding: 6px 0;
  background: transparent;
}

.p-primary-nav__item {
  position: relative;
  width: 36px;
  height: 36px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  color: var(--fg-subtle);
  background: transparent;
  border-radius: var(--r-3);
  transition:
    background var(--dur-fast) var(--ease),
    color var(--dur-fast) var(--ease),
    transform var(--dur-fast) var(--ease);
}

.p-primary-nav__item:hover {
  background: var(--hover);
  color: var(--fg);
}

.p-primary-nav__item:active {
  transform: scale(0.94);
}

.p-primary-nav__item.is-active {
  color: var(--accent);
  background: var(--accent-soft);
}

.p-primary-nav__item.is-active::before {
  content: '';
  position: absolute;
  left: -8px;
  top: 8px;
  bottom: 8px;
  width: 2px;
  border-radius: 2px;
  background: var(--accent);
}

.p-primary-nav__spacer {
  flex: 1;
}
</style>

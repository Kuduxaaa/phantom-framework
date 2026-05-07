<script setup lang="ts">
/**
 * Header shared by every main-content panel: breadcrumb, title, subtitle,
 * actions row, and optional tab strip.
 */

export interface Crumb {
  label: string
  onClick?: () => void
}

export interface PanelTab {
  id: string
  label: string
  count?: number
}

interface Props {
  breadcrumb?: Crumb[]
  title: string
  tabs?: PanelTab[]
  activeTab?: string
}

defineProps<Props>()

defineEmits<{ tab: [id: string] }>()
</script>

<template>
  <header class="p-panel-header">
    <div v-if="breadcrumb && breadcrumb.length" class="p-panel-header__crumbs">
      <template v-for="(c, i) in breadcrumb" :key="i">
        <span v-if="i > 0" class="p-panel-header__crumb-sep">›</span>
        <span
          class="p-panel-header__crumb"
          :class="{ 'is-clickable': !!c.onClick }"
          @click="c.onClick?.()"
        >{{ c.label }}</span>
      </template>
    </div>

    <div class="p-panel-header__main">
      <div class="p-panel-header__titles">
        <h1 class="p-panel-header__title">{{ title }}</h1>
        <div v-if="$slots.subtitle" class="p-panel-header__subtitle">
          <slot name="subtitle" />
        </div>
      </div>
      <div v-if="$slots.actions" class="p-panel-header__actions">
        <slot name="actions" />
      </div>
    </div>

    <div v-if="tabs && tabs.length" class="p-panel-header__tabs">
      <button
        v-for="t in tabs"
        :key="t.id"
        type="button"
        class="p-panel-header__tab"
        :class="{ 'is-active': activeTab === t.id }"
        @click="$emit('tab', t.id)"
      >
        {{ t.label }}
        <span v-if="t.count != null" class="tabular p-panel-header__tab-count">{{ t.count }}</span>
      </button>
    </div>
  </header>
</template>

<style scoped>
.p-panel-header {
  padding: 20px 24px 0;
  border-bottom: 1px solid var(--line);
  background: var(--surface);
  flex-shrink: 0;
}

.p-panel-header__crumbs {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 11px;
  color: var(--fg-subtle);
  margin-bottom: 8px;
}

.p-panel-header__crumb-sep {
  color: var(--fg-faint);
}

.p-panel-header__crumb.is-clickable {
  cursor: pointer;
  transition: color var(--dur-fast) var(--ease);
}

.p-panel-header__crumb.is-clickable:hover {
  color: var(--fg);
  text-decoration: underline;
  text-decoration-color: var(--line-strong);
  text-underline-offset: 3px;
}

.p-panel-header__crumbs > .p-panel-header__crumb:last-of-type {
  color: var(--fg);
  font-weight: 500;
}

.p-panel-header__main {
  display: flex;
  align-items: flex-start;
  gap: 20px;
}

.p-panel-header__titles {
  flex: 1;
  min-width: 0;
}

.p-panel-header__title {
  margin: 0;
  font-family: var(--font-display);
  font-size: 24px;
  font-weight: 600;
  letter-spacing: -0.022em;
  color: var(--fg);
  line-height: 1.15;
}

.p-panel-header__subtitle {
  font-size: var(--t-sm);
  color: var(--fg-muted);
  margin-top: 6px;
}

.p-panel-header__actions {
  display: flex;
  gap: 8px;
  align-items: center;
  flex-shrink: 0;
}

.p-panel-header__tabs {
  display: flex;
  gap: 2px;
  margin-top: 18px;
}

.p-panel-header__tab {
  position: relative;
  padding: 9px 14px;
  font-size: var(--t-sm);
  font-weight: 500;
  color: var(--fg-subtle);
  border-bottom: 1.5px solid transparent;
  margin-bottom: -1px;
  transition: color var(--dur-fast) var(--ease);
}

.p-panel-header__tab:hover {
  color: var(--fg);
}

.p-panel-header__tab.is-active {
  color: var(--fg);
  border-bottom-color: var(--accent);
}

.p-panel-header__tab-count {
  margin-left: 6px;
  font-size: var(--t-xs);
  color: var(--fg-subtle);
}
</style>

<script setup lang="ts">
/**
 * Proxy "History" sub-pane — lightweight filter bar + waterfall + closable detail pane.
 *
 * The detail pane can be closed (clears the proxy store selection) so the
 * traffic list spans the full width — useful for triaging long captures.
 */
import { computed, ref } from 'vue'
import PSearchInput from '../atoms/PSearchInput.vue'
import PIcon from '../atoms/PIcon.vue'
import PIconButton from '../atoms/PIconButton.vue'
import PFilterChip from '../atoms/PFilterChip.vue'
import PMethodChip from '../molecules/PMethodChip.vue'
import PProxyDetail from './PProxyDetail.vue'
import { useProxyStore } from '@/stores/proxy'
import { formatBytes, methodColor, statusColor } from '@/utils/format'
import type { HttpMethod, ProxyEntry } from '@/types'

type StatusClass = 'all' | '2xx' | '3xx' | '4xx' | '5xx'

const proxy = useProxyStore()

const filter = ref<string>('')
const methodFilter = ref<Set<HttpMethod>>(new Set())
const statusFilter = ref<StatusClass>('all')
const advancedOpen = ref<boolean>(false)

const METHODS: HttpMethod[] = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
const STATUS_CLASSES: StatusClass[] = ['all', '2xx', '3xx', '4xx', '5xx']

const filtered = computed<ProxyEntry[]>(() =>
  proxy.items.filter((t) => {
    if (filter.value && !`${t.host}${t.path}`.toLowerCase().includes(filter.value.toLowerCase())) return false
    if (methodFilter.value.size && !methodFilter.value.has(t.method)) return false
    if (statusFilter.value !== 'all') {
      const klass = Math.floor(t.status / 100)
      if (statusFilter.value === '2xx' && klass !== 2) return false
      if (statusFilter.value === '3xx' && klass !== 3) return false
      if (statusFilter.value === '4xx' && klass !== 4) return false
      if (statusFilter.value === '5xx' && klass !== 5) return false
    }
    return true
  }),
)

const maxTs = computed<number>(() => Math.max(...proxy.items.map((t) => t.ts), 1))

const activeFilterCount = computed<number>(
  () =>
    (methodFilter.value.size ? 1 : 0) +
    (statusFilter.value !== 'all' ? 1 : 0),
)

function toggleMethod(m: HttpMethod): void {
  const next = new Set(methodFilter.value)
  if (next.has(m)) next.delete(m)
  else next.add(m)
  methodFilter.value = next
}

function clearFilters(): void {
  filter.value = ''
  methodFilter.value = new Set()
  statusFilter.value = 'all'
}

function rowStartPct(row: ProxyEntry): number {
  return (row.ts / maxTs.value) * 80
}

function rowWidthPct(row: ProxyEntry): number {
  return Math.max(2, (row.dur / 500) * 30)
}

function closeDetail(): void {
  proxy.clearSelection()
}
</script>

<template>
  <div class="p-proxy-history__bar">
    <PSearchInput v-model="filter" placeholder="Filter by host, path, header, or body…" />

    <button
      type="button"
      class="p-proxy-history__filter-btn"
      :class="{ 'is-active': advancedOpen || activeFilterCount > 0 }"
      @click="advancedOpen = !advancedOpen"
    >
      <PIcon name="filter" :size="11" />
      Filters
      <span v-if="activeFilterCount > 0" class="p-proxy-history__filter-badge">{{ activeFilterCount }}</span>
    </button>

    <button
      v-if="filter || activeFilterCount > 0"
      type="button"
      class="p-proxy-history__clear"
      @click="clearFilters"
    >Clear</button>

    <span class="p-proxy-history__spacer" />
    <span class="p-proxy-history__count">
      <span class="tabular">{{ filtered.length }}</span>
      <span class="p-proxy-history__count-of">of {{ proxy.items.length }}</span>
    </span>
  </div>

  <Transition name="p-proxy-history__advanced">
    <div v-if="advancedOpen" class="p-proxy-history__advanced">
      <div class="p-proxy-history__group">
        <span class="label">Method</span>
        <div class="p-proxy-history__chips">
          <PMethodChip
            v-for="m in METHODS"
            :key="m"
            :method="m"
            variant="chip"
            :active="methodFilter.has(m)"
            @click="toggleMethod(m)"
          />
        </div>
      </div>
      <div class="p-proxy-history__group">
        <span class="label">Status</span>
        <div class="p-proxy-history__chips">
          <PFilterChip
            v-for="s in STATUS_CLASSES"
            :key="s"
            variant="flat"
            :active="statusFilter === s"
            @click="statusFilter = s"
          >{{ s }}</PFilterChip>
        </div>
      </div>
    </div>
  </Transition>

  <div class="p-proxy-history__split">
    <div class="p-proxy-history__list">
      <div class="p-proxy-history__head">
        <span class="p-proxy-history__h-method">Method</span>
        <span class="p-proxy-history__h-host">Host</span>
        <span>Path</span>
        <span class="p-proxy-history__h-right p-proxy-history__h-status">Status</span>
        <span class="p-proxy-history__h-right p-proxy-history__h-size">Size</span>
        <span class="p-proxy-history__h-right p-proxy-history__h-time">Time</span>
        <span class="p-proxy-history__h-waterfall">Waterfall</span>
      </div>
      <button
        v-for="row in filtered"
        :key="row.id"
        type="button"
        class="p-proxy-history__row"
        :class="{ 'is-selected': proxy.selectedId === row.id, 'is-intercepted': row.intercepted }"
        @click="proxy.select(row.id)"
      >
        <span v-if="row.intercepted" class="p-proxy-history__rail" />
        <span class="p-proxy-history__cell p-proxy-history__method" :style="{ color: methodColor(row.method) }">
          {{ row.method }}
        </span>
        <span class="p-proxy-history__cell p-proxy-history__host">
          <PIcon v-if="row.is_https" name="lock" :size="9" class="p-proxy-history__lock" />
          <span class="p-proxy-history__truncate">{{ row.host }}</span>
        </span>
        <span class="p-proxy-history__cell p-proxy-history__path">{{ row.path }}</span>
        <span class="p-proxy-history__cell p-proxy-history__h-right" :style="{ color: statusColor(row.status) }">
          {{ row.status }}
        </span>
        <span class="p-proxy-history__cell p-proxy-history__h-right p-proxy-history__sub">
          {{ formatBytes(row.size) }}
        </span>
        <span class="p-proxy-history__cell p-proxy-history__h-right p-proxy-history__sub">
          {{ row.dur }}ms
        </span>
        <span class="p-proxy-history__cell p-proxy-history__waterfall">
          <span
            class="p-proxy-history__bar-mark"
            :style="{
              left: `${rowStartPct(row)}%`,
              width: `${rowWidthPct(row)}%`,
              background: statusColor(row.status),
            }"
          />
        </span>
      </button>
    </div>

    <Transition name="p-proxy-history__detail">
      <aside v-if="proxy.selected" class="p-proxy-history__detail">
        <div class="p-proxy-history__detail-close">
          <PIconButton tooltip="Close detail" tooltip-position="left" @click="closeDetail">
            <PIcon name="close" :size="12" />
          </PIconButton>
        </div>
        <PProxyDetail :request="proxy.selected" />
      </aside>
    </Transition>
  </div>
</template>

<style scoped>
.p-proxy-history__bar {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 16px;
  border-bottom: 1px solid var(--line);
  background: var(--bg-elev);
  flex-shrink: 0;
}

.p-proxy-history__filter-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  height: 26px;
  padding: 0 10px;
  font-size: var(--t-sm);
  font-weight: 500;
  color: var(--fg-muted);
  background: transparent;
  border: 1px solid transparent;
  border-radius: var(--r-2);
  transition:
    background var(--dur-fast) var(--ease),
    color var(--dur-fast) var(--ease),
    border-color var(--dur-fast) var(--ease);
}

.p-proxy-history__filter-btn:hover {
  color: var(--fg);
  background: var(--hover);
}

.p-proxy-history__filter-btn.is-active {
  color: var(--accent);
  background: var(--accent-soft);
}

.p-proxy-history__filter-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 16px;
  height: 16px;
  padding: 0 5px;
  border-radius: var(--r-full);
  background: var(--accent);
  color: var(--accent-text);
  font-family: var(--font-mono);
  font-size: 10px;
  font-weight: 600;
  line-height: 1;
}

.p-proxy-history__clear {
  height: 26px;
  padding: 0 8px;
  font-size: var(--t-sm);
  font-weight: 500;
  color: var(--fg-subtle);
  border-radius: var(--r-2);
  transition: color var(--dur-fast) var(--ease);
}

.p-proxy-history__clear:hover {
  color: var(--fg);
}

.p-proxy-history__spacer {
  flex: 1;
}

.p-proxy-history__count {
  display: inline-flex;
  gap: 4px;
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--fg-muted);
}

.p-proxy-history__count-of {
  color: var(--fg-faint);
}

.p-proxy-history__advanced {
  display: flex;
  gap: 18px;
  padding: 10px 16px;
  border-bottom: 1px solid var(--line);
  background: var(--bg);
  flex-shrink: 0;
}

.p-proxy-history__group {
  display: flex;
  align-items: center;
  gap: 8px;
}

.p-proxy-history__chips {
  display: flex;
  gap: 4px;
}

.p-proxy-history__advanced-enter-active,
.p-proxy-history__advanced-leave-active {
  transition:
    opacity var(--dur-fast) var(--ease),
    max-height var(--dur) var(--ease-out);
  overflow: hidden;
  max-height: 60px;
}

.p-proxy-history__advanced-enter-from,
.p-proxy-history__advanced-leave-to {
  opacity: 0;
  max-height: 0;
  padding-top: 0;
  padding-bottom: 0;
}

.p-proxy-history__split {
  flex: 1;
  display: flex;
  min-height: 0;
}

.p-proxy-history__list {
  flex: 1;
  overflow: auto;
  min-width: 0;
}

.p-proxy-history__head,
.p-proxy-history__row {
  display: grid;
  grid-template-columns: 64px 140px minmax(0, 1fr) 60px 64px 64px 180px;
  gap: 12px;
  align-items: center;
  padding: 6px 16px;
  font-family: var(--font-mono);
  font-size: 11.5px;
}

.p-proxy-history__head {
  padding: 9px 16px;
  position: sticky;
  top: 0;
  background: var(--bg);
  z-index: 1;
  border-bottom: 1px solid var(--line);
  font-size: 10.5px;
  text-transform: uppercase;
  letter-spacing: var(--tracking-label);
  color: var(--fg-subtle);
  font-weight: 500;
  font-family: var(--font-sans);
}

.p-proxy-history__h-right {
  text-align: right;
}

.p-proxy-history__h-method {
  /* keeps header alignment with the row's method cell */
}

.p-proxy-history__row {
  width: 100%;
  text-align: left;
  background: transparent;
  cursor: pointer;
  position: relative;
  border-bottom: 1px solid var(--line-soft);
  transition: background var(--dur-fast) var(--ease);
}

.p-proxy-history__row:hover {
  background: var(--hover);
}

.p-proxy-history__row.is-selected {
  background: var(--selected);
}

.p-proxy-history__rail {
  position: absolute;
  left: 0;
  top: 0;
  bottom: 0;
  width: 2px;
  background: var(--accent);
}

.p-proxy-history__cell {
  min-width: 0;
}

.p-proxy-history__method {
  font-weight: 600;
}

.p-proxy-history__host {
  color: var(--fg-muted);
  display: inline-flex;
  align-items: center;
  gap: 4px;
  overflow: hidden;
}

.p-proxy-history__lock {
  color: var(--fg-faint);
  flex-shrink: 0;
}

.p-proxy-history__truncate {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.p-proxy-history__path {
  color: var(--fg);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.p-proxy-history__sub {
  color: var(--fg-subtle);
  font-variant-numeric: tabular-nums;
}

.p-proxy-history__waterfall {
  position: relative;
  height: 14px;
}

.p-proxy-history__bar-mark {
  position: absolute;
  top: 5px;
  height: 4px;
  opacity: 0.7;
  border-radius: 999px;
}

.p-proxy-history__detail {
  position: relative;
  width: 460px;
  flex-shrink: 0;
  border-left: 1px solid var(--line);
  background: var(--bg-elev);
  display: flex;
}

.p-proxy-history__detail-close {
  position: absolute;
  top: 8px;
  right: 8px;
  z-index: 2;
}

.p-proxy-history__detail-enter-active,
.p-proxy-history__detail-leave-active {
  transition:
    width var(--dur) var(--ease-out),
    opacity var(--dur) var(--ease-out);
}

.p-proxy-history__detail-enter-from,
.p-proxy-history__detail-leave-to {
  width: 0;
  opacity: 0;
}
</style>

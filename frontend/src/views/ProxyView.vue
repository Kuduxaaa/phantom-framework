<script setup lang="ts">
/**
 * Proxy view — sub-application with sessions sidebar and four sub-tabs.
 */
import { computed, ref } from 'vue'
import PSecondaryNav from '@/components/organisms/PSecondaryNav.vue'
import PMainPanel from '@/components/organisms/PMainPanel.vue'
import PProxyHistoryPane from '@/components/organisms/PProxyHistoryPane.vue'
import PProxyInterceptPane from '@/components/organisms/PProxyInterceptPane.vue'
import PProxyRepeaterPane from '@/components/organisms/PProxyRepeaterPane.vue'
import PProxyTimelinePane from '@/components/organisms/PProxyTimelinePane.vue'
import PNavRow from '@/components/molecules/PNavRow.vue'
import PPanelHeader from '@/components/molecules/PPanelHeader.vue'
import type { PanelTab } from '@/components/molecules/PPanelHeader.vue'
import PRunningPulse from '@/components/atoms/PRunningPulse.vue'
import PIcon from '@/components/atoms/PIcon.vue'
import PIconButton from '@/components/atoms/PIconButton.vue'
import PButton from '@/components/atoms/PButton.vue'
import { useProxyStore } from '@/stores/proxy'

type ProxyTab = 'history' | 'intercept' | 'repeater' | 'timeline'

const proxy = useProxyStore()
const tab = ref<ProxyTab>('history')
const scope = ref<'all' | 'in-scope'>('all')

const IN_SCOPE_HOSTS = ['api.acme.io', 'app.acme.io']

const inScope = computed<number>(
  () => proxy.items.filter((t) => IN_SCOPE_HOSTS.includes(t.host)).length,
)

const tabs = computed<PanelTab[]>(() => [
  { id: 'history', label: 'History', count: proxy.items.length },
  { id: 'intercept', label: 'Intercept', count: proxy.intercepted.length },
  { id: 'repeater', label: 'Repeater', count: 3 },
  { id: 'timeline', label: 'Timeline' },
])

const hostsAll = computed(() => {
  const acc: Record<string, number> = {}
  for (const t of proxy.items) acc[t.host] = (acc[t.host] ?? 0) + 1
  return Object.entries(acc).sort((a, b) => b[1] - a[1])
})

const hostsExpanded = ref<boolean>(false)

const hosts = computed(() =>
  hostsExpanded.value ? hostsAll.value : hostsAll.value.slice(0, 5),
)
</script>

<template>
  <PSecondaryNav title="Sessions" footer="mitm CA loaded · :8080">
    <template #action>
      <PIconButton tooltip="New session" shortcut="N"><PIcon name="plus" :size="12" /></PIconButton>
    </template>

    <PNavRow
      active
      label="Live capture"
      :sub="`${proxy.items.length} reqs · ${proxy.intercepted.length} held`"
    >
      <template #leading><PRunningPulse :paused="proxy.paused" /></template>
    </PNavRow>
    <PNavRow label="acme api spelunking" sub="184 requests" trailing="pinned">
      <template #leading><PIcon name="note" :size="12" /></template>
    </PNavRow>
    <PNavRow label="auth flow trace" sub="29 requests">
      <template #leading><PIcon name="note" :size="12" /></template>
    </PNavRow>
    <PNavRow label="2026-05-04" sub="411 requests">
      <template #leading><PIcon name="note" :size="12" /></template>
    </PNavRow>

    <div class="p-proxy__group">
      <div class="label p-proxy__group-label">Scope</div>
      <button
        v-for="s in [
          { id: 'all', label: 'All hosts', count: proxy.items.length },
          { id: 'in-scope', label: 'In-scope only', count: inScope },
        ]"
        :key="s.id"
        type="button"
        class="p-proxy__scope-btn"
        :class="{ 'is-active': scope === s.id }"
        @click="scope = s.id as 'all' | 'in-scope'"
      >
        <span>{{ s.label }}</span>
        <span class="tabular p-proxy__scope-count">{{ s.count }}</span>
      </button>
    </div>

    <div class="p-proxy__group">
      <div class="label p-proxy__group-label">Hosts</div>
      <div v-for="[host, n] in hosts" :key="host" class="p-proxy__host">
        <span class="p-proxy__host-name">{{ host }}</span>
        <span class="tabular p-proxy__host-count">{{ n }}</span>
      </div>
      <button
        v-if="hostsAll.length > 5"
        type="button"
        class="p-proxy__host-more"
        @click="hostsExpanded = !hostsExpanded"
      >
        {{ hostsExpanded ? 'Show less' : `Show ${hostsAll.length - 5} more` }}
      </button>
    </div>
  </PSecondaryNav>

  <PMainPanel>
    <PPanelHeader
      :breadcrumb="[{ label: 'Proxy' }, { label: 'Live capture' }]"
      title="HTTP / HTTPS proxy"
      :tabs="tabs"
      :active-tab="tab"
      @tab="(id: string) => (tab = id as ProxyTab)"
    >
      <template #subtitle>
        <span class="p-proxy__subtitle">
          <PRunningPulse :paused="proxy.paused" />
          <span>{{ proxy.paused ? 'paused' : 'listening' }} · 127.0.0.1:8080</span>
          <span class="p-proxy__sep">·</span>
          <span class="tabular">{{ proxy.items.length }} reqs</span>
          <span class="p-proxy__sep">·</span>
          <span class="tabular p-proxy__err">{{ proxy.errors }} err</span>
          <span class="p-proxy__sep">·</span>
          <span class="tabular p-proxy__held">{{ proxy.intercepted.length }} held</span>
        </span>
      </template>
      <template #actions>
        <PButton variant="ghost" @click="proxy.togglePause()">
          <template #icon>
            <PIcon :name="proxy.paused ? 'play' : 'pause'" :size="12" />
          </template>
          {{ proxy.paused ? 'Resume' : 'Pause' }}
        </PButton>
        <PButton variant="ghost"><template #icon><PIcon name="refresh" :size="12" /></template>Clear</PButton>
        <PButton variant="secondary"><template #icon><PIcon name="external" :size="12" /></template>Export HAR</PButton>
      </template>
    </PPanelHeader>

    <PProxyHistoryPane v-if="tab === 'history'" />
    <PProxyInterceptPane v-else-if="tab === 'intercept'" />
    <PProxyRepeaterPane v-else-if="tab === 'repeater'" />
    <PProxyTimelinePane v-else />
  </PMainPanel>
</template>

<style scoped>
.p-proxy__group {
  margin-top: 14px;
  padding: 0 4px;
}

.p-proxy__group-label {
  padding: 0 6px 6px;
}

.p-proxy__scope-btn {
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
  padding: 5px 8px;
  border-radius: var(--r-2);
  background: transparent;
  color: var(--fg);
  font-size: var(--t-sm);
  text-align: left;
}

.p-proxy__scope-btn:hover {
  background: var(--hover);
}

.p-proxy__scope-btn.is-active {
  background: var(--active);
}

.p-proxy__scope-count {
  font-size: 11px;
  color: var(--fg-subtle);
}

.p-proxy__host {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 4px 8px;
  font-size: 11px;
}

.p-proxy__host-name {
  font-family: var(--font-mono);
  color: var(--fg-muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.p-proxy__host-count {
  color: var(--fg-subtle);
}

.p-proxy__host-more {
  margin-top: 6px;
  width: 100%;
  padding: 5px 8px;
  font-size: 11px;
  color: var(--fg-subtle);
  text-align: left;
  border-radius: var(--r-2);
  transition: color var(--dur-fast) var(--ease), background var(--dur-fast) var(--ease);
}

.p-proxy__host-more:hover {
  color: var(--fg);
  background: var(--hover);
}

.p-proxy__subtitle {
  display: inline-flex;
  align-items: center;
  gap: 10px;
}

.p-proxy__sep {
  color: var(--fg-faint);
}

.p-proxy__err {
  color: var(--err);
}

.p-proxy__held {
  color: var(--accent);
}
</style>

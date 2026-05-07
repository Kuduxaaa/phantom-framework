<script setup lang="ts">
/**
 * Proxy "Timeline" sub-pane — bucketed request histogram, summary stats, top hosts.
 */
import { computed } from 'vue'
import { formatBytes } from '@/utils/format'
import { useProxyStore } from '@/stores/proxy'

const proxy = useProxyStore()
const BUCKETS = 60

interface Bucket {
  errors: number
  ok: number
}

const buckets = computed<Bucket[]>(() => {
  const maxTs = Math.max(...proxy.items.map((t) => t.ts), 1)
  return Array.from({ length: BUCKETS }, (_, i) => {
    const start = (i / BUCKETS) * maxTs
    const end = ((i + 1) / BUCKETS) * maxTs
    const slice = proxy.items.filter((t) => t.ts >= start && t.ts < end)
    return {
      errors: slice.filter((t) => t.status >= 400).length,
      ok: slice.filter((t) => t.status < 400).length,
    }
  })
})

const maxBucket = computed<number>(() =>
  Math.max(...buckets.value.map((b) => b.errors + b.ok), 1),
)

interface SummaryStat {
  label: string
  value: string
  hint: string
  color?: string
}

const stats = computed<SummaryStat[]>(() => {
  const total = proxy.items.length
  const avg = Math.round(proxy.items.reduce((s, t) => s + t.dur, 0) / total)
  const errs = proxy.items.filter((t) => t.status >= 400).length
  const bytes = proxy.items.reduce((s, t) => s + t.size, 0)
  return [
    { label: 'Total', value: String(total), hint: 'requests captured' },
    { label: 'Avg latency', value: `${avg}ms`, hint: 'across all hosts' },
    { label: 'Errors', value: String(errs), hint: '4xx + 5xx', color: 'var(--err)' },
    { label: 'Bytes', value: formatBytes(bytes), hint: 'transferred' },
  ]
})

interface HostStat {
  host: string
  count: number
  errors: number
  avgDur: number
}

const hosts = computed<HostStat[]>(() => {
  const acc: Record<string, { count: number; errors: number; durSum: number }> = {}
  for (const t of proxy.items) {
    const cur = (acc[t.host] ??= { count: 0, errors: 0, durSum: 0 })
    cur.count++
    cur.durSum += t.dur
    if (t.status >= 400) cur.errors++
  }
  return Object.entries(acc)
    .map(([host, v]) => ({ host, count: v.count, errors: v.errors, avgDur: Math.round(v.durSum / v.count) }))
    .sort((a, b) => b.count - a.count)
})
</script>

<template>
  <div class="p-proxy-timeline">
    <section class="p-proxy-timeline__chart-section">
      <div class="label">Requests over time · {{ proxy.items.length }} total</div>
      <div class="p-proxy-timeline__chart">
        <div
          v-for="(b, i) in buckets"
          :key="i"
          class="p-proxy-timeline__bucket"
        >
          <div
            class="p-proxy-timeline__b-err"
            :style="{
              height: `${(b.errors / maxBucket) * 100}%`,
              minHeight: b.errors ? '1px' : '0',
            }"
          />
          <div
            class="p-proxy-timeline__b-ok"
            :style="{
              height: `${(b.ok / maxBucket) * 100}%`,
              minHeight: b.ok ? '1px' : '0',
            }"
          />
        </div>
      </div>
      <div class="p-proxy-timeline__axis">
        <span>0s</span>
        <span>15s</span>
        <span>30s</span>
        <span>45s</span>
        <span>60s</span>
      </div>
    </section>

    <section class="p-proxy-timeline__stats">
      <div v-for="s in stats" :key="s.label" class="p-proxy-timeline__stat">
        <div class="label">{{ s.label }}</div>
        <div class="tabular p-proxy-timeline__stat-value" :style="{ color: s.color || 'var(--fg)' }">
          {{ s.value }}
        </div>
        <div class="p-proxy-timeline__stat-hint">{{ s.hint }}</div>
      </div>
    </section>

    <section>
      <div class="label p-proxy-timeline__hosts-label">Top hosts</div>
      <div class="p-proxy-timeline__hosts">
        <div v-for="h in hosts" :key="h.host" class="p-proxy-timeline__host-row">
          <span class="p-proxy-timeline__host-name">{{ h.host }}</span>
          <span class="tabular p-proxy-timeline__host-cell">{{ h.count }} reqs</span>
          <span
            class="tabular p-proxy-timeline__host-cell"
            :class="{ 'has-errors': h.errors > 0 }"
          >{{ h.errors }} err</span>
          <span class="tabular p-proxy-timeline__host-cell">{{ h.avgDur }}ms avg</span>
        </div>
      </div>
    </section>
  </div>
</template>

<style scoped>
.p-proxy-timeline {
  flex: 1;
  overflow: auto;
  padding: 20px;
}

.p-proxy-timeline__chart-section {
  margin-bottom: 18px;
}

.p-proxy-timeline__chart {
  display: flex;
  align-items: flex-end;
  gap: 1px;
  height: 80px;
  border-bottom: 1px solid var(--line);
  margin-top: 8px;
}

.p-proxy-timeline__bucket {
  flex: 1;
  display: flex;
  flex-direction: column;
  justify-content: flex-end;
}

.p-proxy-timeline__b-err {
  background: var(--err);
}

.p-proxy-timeline__b-ok {
  background: var(--fg-muted);
  opacity: 0.6;
}

.p-proxy-timeline__axis {
  display: flex;
  justify-content: space-between;
  font-size: 10.5px;
  color: var(--fg-faint);
  font-family: var(--font-mono);
  margin-top: 6px;
}

.p-proxy-timeline__stats {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
  margin-bottom: 20px;
}

.p-proxy-timeline__stat {
  padding: 14px;
  border: 1px solid var(--line);
  border-radius: var(--r-2);
  background: var(--surface);
}

.p-proxy-timeline__stat-value {
  font-size: 22px;
  font-weight: 500;
  letter-spacing: -0.02em;
  margin-top: 6px;
}

.p-proxy-timeline__stat-hint {
  font-size: 11px;
  color: var(--fg-subtle);
  margin-top: 2px;
}

.p-proxy-timeline__hosts-label {
  margin-bottom: 8px;
}

.p-proxy-timeline__hosts {
  border: 1px solid var(--line);
  border-radius: var(--r-2);
  background: var(--surface);
}

.p-proxy-timeline__host-row {
  display: grid;
  grid-template-columns: 1fr 80px 80px 80px;
  padding: 10px 14px;
  align-items: center;
  gap: 10px;
  border-top: 1px solid var(--line-soft);
}

.p-proxy-timeline__host-row:first-child {
  border-top: 0;
}

.p-proxy-timeline__host-name {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--fg);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.p-proxy-timeline__host-cell {
  font-size: 11px;
  color: var(--fg-muted);
  text-align: right;
}

.p-proxy-timeline__host-cell.has-errors {
  color: var(--err);
}
</style>

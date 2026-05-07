<script setup lang="ts">
/**
 * Selected-request detail aside — request/response/headers/cookies/timing tabs.
 */
import { computed, ref } from 'vue'
import PIcon from '../atoms/PIcon.vue'
import PButton from '../atoms/PButton.vue'
import { methodColor, statusColor } from '@/utils/format'
import type { ProxyEntry } from '@/types'

interface Props {
  request: ProxyEntry
}

const props = defineProps<Props>()

type DetailTab = 'request' | 'response' | 'headers' | 'cookies' | 'timing'

const tab = ref<DetailTab>('request')

const TABS: { id: DetailTab; label: string }[] = [
  { id: 'request', label: 'Request' },
  { id: 'response', label: 'Response' },
  { id: 'headers', label: 'Headers' },
  { id: 'cookies', label: 'Cookies' },
  { id: 'timing', label: 'Timing' },
]

const REQ_HEADERS = computed<Array<[string, string]>>(() => [
  ['Host', props.request.host],
  ['User-Agent', 'Mozilla/5.0 phantom-proxy'],
  ['Accept', props.request.mime],
  ['Authorization', 'Bearer eyJhbGciOiJIUzI1Ni…'],
  ['Cookie', 'session=a8f3…; csrf=4d11'],
  ['X-Request-Id', '01HE7…'],
])

const RES_HEADERS = computed<Array<[string, string]>>(() => [
  ['Content-Type', props.request.mime],
  ['Content-Length', String(props.request.size)],
  ['Server', 'nginx/1.24.0'],
  ['Strict-Transport-Security', 'max-age=63072000'],
  ['X-Frame-Options', 'DENY'],
  ['Set-Cookie', 'session=b7e2…; Secure; HttpOnly'],
])

const COOKIES: Array<[string, string, string, string]> = [
  ['session', 'a8f3c2e1d9b4…', '.acme.io', 'HttpOnly'],
  ['csrf', '4d11ee93a7…', '.acme.io', 'Secure'],
  ['theme', 'dark', '.acme.io', '—'],
]

interface TimingPhase {
  label: string
  ratio: number
  color: string
}

const PHASE_DEFS: TimingPhase[] = [
  { label: 'DNS', ratio: 0.04, color: 'var(--sev-info)' },
  { label: 'Connect', ratio: 0.10, color: 'var(--sev-medium)' },
  { label: 'TLS', ratio: 0.18, color: 'var(--accent)' },
  { label: 'Send', ratio: 0.05, color: 'var(--ok)' },
  { label: 'Wait (TTFB)', ratio: 0.55, color: 'var(--fg-muted)' },
  { label: 'Receive', ratio: 0.08, color: 'var(--sev-low)' },
]

const phases = computed(() =>
  PHASE_DEFS.map((p) => ({ ...p, ms: Math.round(props.request.dur * p.ratio) })),
)

const phaseTotal = computed<number>(() => phases.value.reduce((s, p) => s + p.ms, 0))

const idTail = computed<string>(() => String(props.request.id).slice(-3))
</script>

<template>
  <aside class="p-proxy-detail">
    <header class="p-proxy-detail__head">
      <div class="p-proxy-detail__id">REQUEST · #{{ idTail }}</div>
      <div class="p-proxy-detail__line">
        <span
          class="pill p-proxy-detail__method"
          :style="{ background: methodColor(request.method), color: 'var(--accent-text)' }"
        >{{ request.method }}</span>
        <span class="p-proxy-detail__url">
          {{ request.is_https ? 'https://' : 'http://' }}{{ request.host }}{{ request.path }}
        </span>
      </div>
      <div class="p-proxy-detail__quick">
        <PButton size="sm" variant="ghost"><template #icon><PIcon name="refresh" :size="11" /></template>Replay</PButton>
        <PButton size="sm" variant="ghost"><template #icon><PIcon name="arrow-right" :size="11" /></template>To repeater</PButton>
        <PButton size="sm" variant="ghost"><template #icon><PIcon name="bug" :size="11" /></template>To intruder</PButton>
        <PButton size="sm" variant="ghost"><template #icon><PIcon name="copy" :size="11" /></template>cURL</PButton>
      </div>
    </header>

    <div class="p-proxy-detail__tabs">
      <button
        v-for="t in TABS"
        :key="t.id"
        type="button"
        class="p-proxy-detail__tab"
        :class="{ 'is-active': tab === t.id }"
        @click="tab = t.id"
      >{{ t.label }}</button>
    </div>

    <div class="p-proxy-detail__body">
      <pre v-if="tab === 'request'" class="p-proxy-detail__pre"><code><span :style="{ color: methodColor(request.method) }">{{ request.method }}</span> <span class="p-proxy-detail__path">{{ request.path }}</span> HTTP/1.1
<span class="p-proxy-detail__h">Host:</span> {{ request.host }}
<span class="p-proxy-detail__h">User-Agent:</span> Mozilla/5.0 phantom-proxy
<span class="p-proxy-detail__h">Accept:</span> {{ request.mime }}
<span class="p-proxy-detail__h">Authorization:</span> Bearer eyJhbGc…
<span class="p-proxy-detail__h">Cookie:</span> session=a8f3…<template v-if="request.method === 'POST'">

{
  "username": "admin",
  "password": "***"
}</template>
</code></pre>

      <pre v-else-if="tab === 'response'" class="p-proxy-detail__pre"><code>HTTP/1.1 <span :style="{ color: statusColor(request.status) }">{{ request.status }}</span> {{ request.status === 200 ? 'OK' : '' }}
<span class="p-proxy-detail__h">Content-Type:</span> {{ request.mime }}
<span class="p-proxy-detail__h">Content-Length:</span> {{ request.size }}
<span class="p-proxy-detail__h">Server:</span> nginx/1.24.0
<template v-if="request.mime.includes('json')">
{
  "data": [...],
  "meta": { "total": 47, "page": 1 }
}</template><template v-if="request.mime.includes('html')">
&lt;!DOCTYPE html&gt;
&lt;html&gt;
  &lt;head&gt;...</template>
</code></pre>

      <div v-else-if="tab === 'headers'" class="p-proxy-detail__headers">
        <div class="p-proxy-detail__hgroup">
          <div class="label p-proxy-detail__hgroup-label">Request headers</div>
          <div class="p-proxy-detail__htable">
            <div v-for="([k, v]) in REQ_HEADERS" :key="k" class="p-proxy-detail__hrow">
              <span class="p-proxy-detail__hkey">{{ k }}</span>
              <span class="p-proxy-detail__hval">{{ v }}</span>
            </div>
          </div>
        </div>
        <div class="p-proxy-detail__hgroup">
          <div class="label p-proxy-detail__hgroup-label">Response headers</div>
          <div class="p-proxy-detail__htable">
            <div v-for="([k, v]) in RES_HEADERS" :key="k" class="p-proxy-detail__hrow">
              <span class="p-proxy-detail__hkey">{{ k }}</span>
              <span class="p-proxy-detail__hval">{{ v }}</span>
            </div>
          </div>
        </div>
      </div>

      <div v-else-if="tab === 'cookies'" class="p-proxy-detail__cookies">
        <div class="label p-proxy-detail__hgroup-label">Cookies</div>
        <div class="p-proxy-detail__ctable">
          <div v-for="h in ['Name', 'Value', 'Domain', 'Flags']" :key="h" class="label p-proxy-detail__chead">
            {{ h }}
          </div>
          <template v-for="(row, ri) in COOKIES" :key="ri">
            <div
              v-for="(c, ci) in row"
              :key="`${ri}-${ci}`"
              class="p-proxy-detail__ccell"
              :class="{ 'is-name': ci === 0 }"
            >{{ c }}</div>
          </template>
        </div>
      </div>

      <div v-else-if="tab === 'timing'" class="p-proxy-detail__timing">
        <div class="label">Timing breakdown · {{ phaseTotal }}ms</div>
        <div v-for="p in phases" :key="p.label" class="p-proxy-detail__phase">
          <span class="p-proxy-detail__phase-label">{{ p.label }}</span>
          <div class="p-proxy-detail__phase-track">
            <div
              class="p-proxy-detail__phase-fill"
              :style="{ width: `${(p.ms / phaseTotal) * 100}%`, background: p.color }"
            />
          </div>
          <span class="tabular p-proxy-detail__phase-ms">{{ p.ms }}ms</span>
        </div>
      </div>
    </div>
  </aside>
</template>

<style scoped>
.p-proxy-detail {
  width: 480px;
  flex-shrink: 0;
  border-left: 1px solid var(--line);
  background: var(--bg-elev);
  display: flex;
  flex-direction: column;
}

.p-proxy-detail__head {
  padding: 12px 16px;
  border-bottom: 1px solid var(--line);
}

.p-proxy-detail__id {
  font-size: 10.5px;
  font-family: var(--font-mono);
  color: var(--fg-subtle);
  margin-bottom: 4px;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.p-proxy-detail__line {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 10px;
}

.p-proxy-detail__method {
  font-family: var(--font-mono);
  font-weight: 600;
  border: 0;
}

.p-proxy-detail__url {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--fg);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  flex: 1;
  min-width: 0;
}

.p-proxy-detail__quick {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
}

.p-proxy-detail__tabs {
  display: flex;
  border-bottom: 1px solid var(--line);
  padding: 0 16px;
  flex-shrink: 0;
}

.p-proxy-detail__tab {
  padding: 8px 10px;
  font-size: var(--t-sm);
  font-weight: 500;
  color: var(--fg-subtle);
  border-bottom: 1.5px solid transparent;
  margin-bottom: -1px;
}

.p-proxy-detail__tab.is-active {
  color: var(--fg);
  border-bottom-color: var(--fg);
}

.p-proxy-detail__body {
  flex: 1;
  overflow: auto;
  min-height: 0;
}

.p-proxy-detail__pre {
  margin: 0;
  padding: 16px;
  font-family: var(--font-mono);
  font-size: 11px;
  line-height: 1.7;
  color: var(--fg);
}

.p-proxy-detail__h {
  color: var(--fg-subtle);
}

.p-proxy-detail__path {
  color: var(--accent);
}

.p-proxy-detail__headers {
  padding: 12px;
}

.p-proxy-detail__hgroup {
  margin-bottom: 14px;
}

.p-proxy-detail__hgroup-label {
  margin-bottom: 6px;
  padding: 0 4px;
}

.p-proxy-detail__htable {
  border: 1px solid var(--line);
  border-radius: var(--r-2);
  background: var(--surface);
}

.p-proxy-detail__hrow {
  display: grid;
  grid-template-columns: 160px 1fr;
  padding: 6px 10px;
  gap: 12px;
  align-items: baseline;
  border-top: 1px solid var(--line-soft);
  font-family: var(--font-mono);
  font-size: 11px;
}

.p-proxy-detail__hrow:first-child {
  border-top: 0;
}

.p-proxy-detail__hkey {
  color: var(--fg-subtle);
}

.p-proxy-detail__hval {
  color: var(--fg);
  word-break: break-all;
}

.p-proxy-detail__cookies {
  padding: 12px;
}

.p-proxy-detail__ctable {
  display: grid;
  grid-template-columns: 110px 1fr 80px 60px;
  border: 1px solid var(--line);
  border-radius: var(--r-2);
  background: var(--surface);
  overflow: hidden;
}

.p-proxy-detail__chead {
  padding: 6px 10px;
  border-bottom: 1px solid var(--line);
  background: var(--bg-elev);
}

.p-proxy-detail__ccell {
  padding: 6px 10px;
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--fg-muted);
  border-top: 1px solid var(--line-soft);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.p-proxy-detail__ccell.is-name {
  color: var(--fg);
}

.p-proxy-detail__timing {
  padding: 14px;
}

.p-proxy-detail__phase {
  display: grid;
  grid-template-columns: 110px 1fr 50px;
  gap: 10px;
  align-items: center;
  padding: 5px 0;
}

.p-proxy-detail__phase-label {
  font-size: 11px;
  color: var(--fg-muted);
}

.p-proxy-detail__phase-track {
  height: 6px;
  background: var(--line-soft);
  border-radius: 999px;
  overflow: hidden;
}

.p-proxy-detail__phase-fill {
  height: 100%;
}

.p-proxy-detail__phase-ms {
  font-size: 11px;
  color: var(--fg-subtle);
  text-align: right;
  font-family: var(--font-mono);
}
</style>

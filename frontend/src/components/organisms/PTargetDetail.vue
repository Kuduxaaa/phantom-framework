<script setup lang="ts">
/**
 * Target detail panel — header + tabs (overview, assets, findings, scans, notes).
 *
 * Owns the active tab; re-renders the appropriate tab body. Findings clicks
 * push the finding into the inspector via the findings store.
 */
import { computed, ref } from 'vue'
import PPanelHeader from '../molecules/PPanelHeader.vue'
import type { PanelTab } from '../molecules/PPanelHeader.vue'
import PRiskMeter from '../atoms/PRiskMeter.vue'
import PIcon from '../atoms/PIcon.vue'
import PButton from '../atoms/PButton.vue'
import PStat from '../atoms/PStat.vue'
import PSection from '../atoms/PSection.vue'
import PSeverityBadge from '../atoms/PSeverityBadge.vue'
import PStatusPill from '../atoms/PStatusPill.vue'
import PScanStatusPill from '../molecules/PScanStatusPill.vue'
import PEmptyTorii from '../atoms/PEmptyTorii.vue'
import PAssetTree, { type AssetNode } from '../molecules/PAssetTree.vue'
import { useFindingsStore } from '@/stores/findings'
import { fmtRel } from '@/utils/time'
import type { AssetStatus, ScanStatus, ScanType, Target } from '@/types'

interface Props {
  target: Target
}

const props = defineProps<Props>()
const findings = useFindingsStore()

type TabId = 'overview' | 'assets' | 'findings' | 'scans' | 'notes'

const tab = ref<TabId>('overview')

const tabs = computed<PanelTab[]>(() => [
  { id: 'overview', label: 'Overview' },
  { id: 'assets', label: 'Assets', count: props.target.assets_count },
  { id: 'findings', label: 'Findings', count: props.target.findings_count },
  { id: 'scans', label: 'Scans' },
  { id: 'notes', label: 'Notes' },
])

const targetFindings = computed(() => findings.byTarget(props.target.id))

const ASSET_TREE: AssetNode[] = [
  {
    type: 'SUBDOMAIN',
    label: 'api.acme.io',
    children: [
      {
        type: 'PORT',
        label: '443/tcp · https · nginx 1.24.0',
        children: [
          {
            type: 'ENDPOINT',
            label: '/v2/users',
            children: [
              { type: 'PARAMETER', label: '?q (string)', sensitive: true },
              { type: 'PARAMETER', label: '?limit (int)' },
            ],
          },
          { type: 'ENDPOINT', label: '/v2/auth/refresh', sensitive: true },
          { type: 'ENDPOINT', label: '/v2/sessions/{id}' },
        ],
      },
      { type: 'PORT', label: '80/tcp · http (redirects)' },
    ],
  },
  {
    type: 'JAVASCRIPT',
    label: '/static/js/main.js',
    sensitive: true,
    children: [{ type: 'API_KEY', label: 'AWS access key (AKIAI…)', sensitive: true }],
  },
]

interface AssetRow {
  type: string
  value: string
  source: string
  confidence: number
  status: AssetStatus
  first_seen: string
  sensitive?: boolean
}

const ASSETS: AssetRow[] = [
  { type: 'SUBDOMAIN', value: 'api.acme.io', source: 'crt.sh', confidence: 100, status: 'VERIFIED', first_seen: '2 days ago' },
  { type: 'SUBDOMAIN', value: 'staging-api.acme.io', source: 'subfinder', confidence: 95, status: 'VERIFIED', first_seen: '2 days ago' },
  { type: 'ENDPOINT', value: '/v2/users', source: 'crawler', confidence: 100, status: 'NEW', first_seen: '8m ago' },
  { type: 'ENDPOINT', value: '/v2/auth/refresh', source: 'crawler', confidence: 100, status: 'NEW', first_seen: '8m ago' },
  { type: 'PARAMETER', value: 'q (string)', source: 'crawler', confidence: 100, status: 'NEW', first_seen: '8m ago' },
  { type: 'JAVASCRIPT', value: '/static/js/main.js', source: 'crawler', confidence: 100, status: 'CHANGED', first_seen: '8m ago' },
  { type: 'API_KEY', value: 'AKIA...EXAMPLE', source: 'js-analysis', confidence: 90, status: 'NEW', first_seen: '4h ago', sensitive: true },
  { type: 'TECHNOLOGY', value: 'FastAPI 0.109.0', source: 'wappalyzer', confidence: 100, status: 'VERIFIED', first_seen: '2d ago' },
  { type: 'PORT', value: '443/tcp', source: 'nmap', confidence: 100, status: 'VERIFIED', first_seen: '2d ago' },
  { type: 'SSL_CERT', value: '*.acme.io · expires 2026-08-12', source: 'tls-probe', confidence: 100, status: 'VERIFIED', first_seen: '2d ago' },
]

const ASSET_STATUS_COLORS: Record<AssetStatus, string> = {
  NEW: 'var(--accent)',
  VERIFIED: 'var(--ok)',
  CHANGED: 'var(--warn)',
  REMOVED: 'var(--fg-subtle)',
  MONITORED: 'var(--sev-info)',
}

interface ScanRow {
  id: number
  type: ScanType
  status: ScanStatus
  started: string
  duration: string
  requests: number | null
  findings: number
}

const SCANS: ScanRow[] = [
  { id: 9001, type: 'VULNERABILITY_SCAN', status: 'COMPLETED', started: '8m ago', duration: '16.4s', requests: 247, findings: 4 },
  { id: 9000, type: 'WEB_CRAWL', status: 'COMPLETED', started: '12m ago', duration: '9.2s', requests: 184, findings: 0 },
  { id: 8998, type: 'SUBDOMAIN_ENUM', status: 'COMPLETED', started: '2h ago', duration: '47s', requests: null, findings: 0 },
  { id: 8995, type: 'VULNERABILITY_SCAN', status: 'FAILED', started: '5h ago', duration: '2.1s', requests: 18, findings: 0 },
  { id: 8990, type: 'TECHNOLOGY_DETECTION', status: 'COMPLETED', started: '1d ago', duration: '4.0s', requests: 12, findings: 0 },
]
</script>

<template>
  <PPanelHeader
    :breadcrumb="[{ label: 'Acme Corp' }, { label: 'Targets' }, { label: target.identifier }]"
    :title="target.identifier"
    :tabs="tabs"
    :active-tab="tab"
    @tab="(id: string) => (tab = id as TabId)"
  >
    <template #subtitle>
      <span class="p-target-detail__subtitle">
        <span>{{ target.target_type.toLowerCase() }}</span>
        <template v-if="target.ip_address">
          <span class="p-target-detail__sep">·</span>
          <span class="p-target-detail__ip">{{ target.ip_address }}</span>
        </template>
        <span class="p-target-detail__sep">·</span>
        <PRiskMeter :score="target.risk_score" :width="60" />
      </span>
    </template>
    <template #actions>
      <PButton variant="ghost"><template #icon><PIcon name="refresh" :size="12" /></template>Re-scan</PButton>
      <PButton variant="ghost"><template #icon><PIcon name="external" :size="12" /></template>Open</PButton>
      <PButton variant="primary"><template #icon><PIcon name="scan" :size="12" /></template>Run scan</PButton>
    </template>
  </PPanelHeader>

  <div class="p-target-detail__body">
    <template v-if="tab === 'overview'">
      <div class="p-target-detail__overview">
        <div class="p-target-detail__stats">
          <PStat
            label="Status"
            :value="target.status.toLowerCase()"
            :mono="false"
            :value-color="target.status === 'VULNERABLE' ? 'var(--sev-high)' : 'var(--fg)'"
          />
          <PStat label="Assets" :value="target.assets_count" divider />
          <PStat
            label="Findings"
            :value="target.findings_count"
            :value-color="target.findings_count > 0 ? 'var(--sev-high)' : 'var(--fg)'"
            divider
          />
          <PStat label="Risk" :value="target.risk_score" divider />
        </div>

        <PSection v-if="target.tech_stack.length" title="Detected technology">
          <div class="p-target-detail__tech">
            <span v-for="t in target.tech_stack" :key="t" class="p-target-detail__tech-pill">
              {{ t }}
            </span>
          </div>
        </PSection>

        <PSection title="Asset hierarchy">
          <template #action>
            <PButton variant="ghost"><template #icon><PIcon name="layers" :size="12" /></template>Graph view</PButton>
          </template>
          <PAssetTree :nodes="ASSET_TREE" />
        </PSection>

        <PSection title="Findings">
          <PEmptyTorii
            v-if="!targetFindings.length"
            title="No findings yet"
            hint="Run a scan against this target to surface vulnerabilities."
          />
          <table v-else class="p-target-detail__find-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Title</th>
                <th>Status</th>
                <th>Signature</th>
                <th class="p-target-detail__col-right">Created</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="f in targetFindings"
                :key="f.id"
                class="p-target-detail__find-row"
                @click="findings.inspect(f.id)"
              >
                <td><PSeverityBadge :level="f.severity" /></td>
                <td>{{ f.title }}</td>
                <td><PStatusPill :status="f.status" /></td>
                <td class="p-target-detail__mono">{{ f.signature_id }}</td>
                <td class="p-target-detail__col-right p-target-detail__age">{{ fmtRel(f.created_at) }}</td>
              </tr>
            </tbody>
          </table>
        </PSection>
      </div>
    </template>

    <template v-if="tab === 'assets'">
      <table class="p-target-detail__assets">
        <thead>
          <tr>
            <th>Type</th>
            <th>Value</th>
            <th>Source</th>
            <th class="p-target-detail__col-right">Conf.</th>
            <th>Status</th>
            <th>First seen</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(a, i) in ASSETS" :key="i">
            <td class="p-target-detail__a-type">{{ a.type.toLowerCase().replace('_', '·') }}</td>
            <td class="p-target-detail__a-value" :class="{ 'is-sensitive': a.sensitive }">{{ a.value }}</td>
            <td class="p-target-detail__a-source">{{ a.source }}</td>
            <td class="p-target-detail__col-right p-target-detail__a-conf">{{ a.confidence }}</td>
            <td>
              <span class="p-target-detail__a-status" :style="{ color: ASSET_STATUS_COLORS[a.status] }">
                <span class="p-target-detail__a-status-dot" :style="{ background: ASSET_STATUS_COLORS[a.status] }" />
                {{ a.status.toLowerCase() }}
              </span>
            </td>
            <td class="p-target-detail__a-seen">{{ a.first_seen }}</td>
          </tr>
        </tbody>
      </table>
    </template>

    <template v-if="tab === 'findings'">
      <PEmptyTorii
        v-if="!targetFindings.length"
        title="No findings yet"
        hint="Run a scan against this target to surface vulnerabilities."
      />
      <table v-else class="p-target-detail__find-table p-target-detail__find-table--full">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Title</th>
            <th>Status</th>
            <th>Signature</th>
            <th class="p-target-detail__col-right">Created</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="f in targetFindings"
            :key="f.id"
            class="p-target-detail__find-row"
            @click="findings.inspect(f.id)"
          >
            <td><PSeverityBadge :level="f.severity" /></td>
            <td>{{ f.title }}</td>
            <td><PStatusPill :status="f.status" /></td>
            <td class="p-target-detail__mono">{{ f.signature_id }}</td>
            <td class="p-target-detail__col-right p-target-detail__age">{{ fmtRel(f.created_at) }}</td>
          </tr>
        </tbody>
      </table>
    </template>

    <template v-if="tab === 'scans'">
      <table class="p-target-detail__scans">
        <thead>
          <tr>
            <th>#</th>
            <th>Scan type</th>
            <th>Status</th>
            <th>Duration</th>
            <th class="p-target-detail__col-right">Requests</th>
            <th class="p-target-detail__col-right">Findings</th>
            <th>Started</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="s in SCANS" :key="s.id">
            <td class="p-target-detail__s-id">#{{ s.id }}</td>
            <td class="p-target-detail__s-type">{{ s.type.toLowerCase() }}</td>
            <td><PScanStatusPill :status="s.status" /></td>
            <td class="p-target-detail__s-dur">{{ s.duration }}</td>
            <td class="p-target-detail__col-right p-target-detail__s-reqs">{{ s.requests ?? '—' }}</td>
            <td
              class="p-target-detail__col-right p-target-detail__s-finds"
              :class="{ 'has-findings': s.findings > 0 }"
            >{{ s.findings }}</td>
            <td class="p-target-detail__s-started">{{ s.started }}</td>
          </tr>
        </tbody>
      </table>
    </template>

    <template v-if="tab === 'notes'">
      <PEmptyTorii
        title="No notes yet"
        hint="Pin findings, methodology, or todos here — they stay scoped to this target."
      />
    </template>
  </div>
</template>

<style scoped>
.p-target-detail__subtitle {
  display: inline-flex;
  align-items: center;
  gap: 10px;
}

.p-target-detail__sep {
  color: var(--fg-faint);
}

.p-target-detail__ip {
  font-family: var(--font-mono);
}

.p-target-detail__body {
  flex: 1;
  overflow-y: auto;
  padding: var(--s-8) var(--s-10);
}

.p-target-detail__overview {
  display: grid;
  gap: var(--s-9);
  max-width: 1100px;
}

.p-target-detail__stats {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  border-top: 1px solid var(--line);
  border-bottom: 1px solid var(--line);
}

.p-target-detail__tech {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.p-target-detail__tech-pill {
  font-size: var(--t-sm);
  padding: 3px 8px;
  font-family: var(--font-mono);
  color: var(--fg-muted);
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: var(--r-1);
}

.p-target-detail__find-table,
.p-target-detail__assets,
.p-target-detail__scans {
  width: 100%;
  border-collapse: collapse;
  border-top: 1px solid var(--line);
  font-size: var(--t-sm);
}

.p-target-detail__find-table--full {
  border-top: 0;
}

.p-target-detail__find-table th,
.p-target-detail__assets th,
.p-target-detail__scans th {
  font-size: var(--t-xs);
  text-transform: uppercase;
  letter-spacing: var(--tracking-label);
  color: var(--fg-subtle);
  font-weight: 500;
  text-align: left;
  padding: 8px 10px;
  border-bottom: 1px solid var(--line);
}

.p-target-detail__find-table td,
.p-target-detail__assets td,
.p-target-detail__scans td {
  padding: 8px 10px;
  border-bottom: 1px solid var(--line-soft);
  color: var(--fg);
  vertical-align: middle;
}

.p-target-detail__find-row {
  cursor: pointer;
  transition: background var(--dur-fast) var(--ease);
}

.p-target-detail__find-row:hover td {
  background: var(--hover);
}

.p-target-detail__col-right {
  text-align: right;
}

.p-target-detail__age {
  color: var(--fg-subtle);
  font-size: var(--t-xs);
}

.p-target-detail__mono {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--fg-muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 200px;
}

.p-target-detail__a-type {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--fg-subtle);
  text-transform: lowercase;
}

.p-target-detail__a-value {
  font-family: var(--font-mono);
  color: var(--fg);
}

.p-target-detail__a-value.is-sensitive {
  color: var(--sev-high);
}

.p-target-detail__a-source {
  color: var(--fg-muted);
}

.p-target-detail__a-conf {
  color: var(--fg-muted);
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
}

.p-target-detail__a-status {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-size: var(--t-xs);
  text-transform: uppercase;
  letter-spacing: var(--tracking-label);
  font-weight: 500;
}

.p-target-detail__a-status-dot {
  width: 5px;
  height: 5px;
  border-radius: 999px;
}

.p-target-detail__a-seen {
  color: var(--fg-subtle);
  font-size: var(--t-xs);
}

.p-target-detail__s-id {
  font-family: var(--font-mono);
  color: var(--fg-faint);
}

.p-target-detail__s-type {
  font-family: var(--font-mono);
  color: var(--fg);
  font-size: 12px;
}

.p-target-detail__s-dur,
.p-target-detail__s-reqs,
.p-target-detail__s-finds {
  color: var(--fg-muted);
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
}

.p-target-detail__s-finds.has-findings {
  color: var(--sev-high);
}

.p-target-detail__s-started {
  color: var(--fg-subtle);
}
</style>

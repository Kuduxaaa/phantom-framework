<script setup lang="ts">
/**
 * Right-side finding inspector — overview / evidence / fix / timeline tabs.
 *
 * Reads the inspected finding from the store and renders nothing when no
 * finding is selected.
 */
import { ref } from 'vue'
import PIcon from '../atoms/PIcon.vue'
import PIconButton from '../atoms/PIconButton.vue'
import PSeverityBadge from '../atoms/PSeverityBadge.vue'
import PStatusPill from '../atoms/PStatusPill.vue'
import PCodeBlock from '../atoms/PCodeBlock.vue'
import PButton from '../atoms/PButton.vue'
import PKeyValue from '../molecules/PKeyValue.vue'
import PEvidencePane from '../molecules/PEvidencePane.vue'
import { useFindingsStore } from '@/stores/findings'
import { fmtRel } from '@/utils/time'

type InspectorTab = 'overview' | 'evidence' | 'remediation' | 'history'

const findings = useFindingsStore()
const tab = ref<InspectorTab>('overview')

const TABS: { id: InspectorTab; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'evidence', label: 'Evidence' },
  { id: 'remediation', label: 'Fix' },
  { id: 'history', label: 'Timeline' },
]

const REQUEST_BODY = `GET /v2/users?q=1' HTTP/1.1
Host: api.acme.io
Authorization: Bearer eyJhbGciOiJIUzI1Ni...
User-Agent: phantom/1.0
Accept: */*
`

const RESPONSE_BODY = `HTTP/1.1 500 Internal Server Error
Content-Type: application/json
Content-Length: 187
Server: nginx/1.24.0

{
  "error": "internal_error",
  "message": "PostgreSQL ERROR: unterminated quoted string at or near \\"1''\\""
}
`

const TIMELINE = [
  { when: 'just now', who: 'system', text: 'Finding created from scan #9001' },
  { when: '8m ago', who: 'system', text: 'Re-test queued — awaiting capacity' },
  { when: '12m ago', who: 'kuduxaaa', text: 'Status changed: NEW → TRIAGING' },
  { when: '14m ago', who: 'kuduxaaa', text: 'Comment: "Confirmed reproducible. CWE-89."' },
  { when: '18m ago', who: 'system', text: 'Linked to signature sql-injection-error-based v1.4' },
] as const

const REFERENCES = [
  ['CWE-89: SQL Injection', 'cwe.mitre.org/data/definitions/89'],
  ['OWASP Top 10 — A03:2021 Injection', 'owasp.org/Top10/A03_2021-Injection'],
  ['SQLAlchemy: Using parameters', 'docs.sqlalchemy.org/en/20/core/tutorial.html'],
] as const

function close(): void {
  findings.inspect(null)
}
</script>

<template>
  <Transition name="p-finding-inspector">
    <aside v-if="findings.inspected" class="p-finding-inspector">
    <header class="p-finding-inspector__head">
      <PSeverityBadge :level="findings.inspected.severity" />
      <div class="p-finding-inspector__head-body">
        <div class="p-finding-inspector__title">{{ findings.inspected.title }}</div>
        <div class="p-finding-inspector__meta">
          <PStatusPill :status="findings.inspected.status" />
          <span class="p-finding-inspector__cwe">{{ findings.inspected.cwe_id }}</span>
          <span>·</span>
          <span class="p-finding-inspector__cvss">CVSS {{ findings.inspected.cvss_score }}</span>
          <span>·</span>
          <span>created {{ fmtRel(findings.inspected.created_at) }}</span>
        </div>
      </div>
      <PIconButton tooltip="Close" shortcut="esc" tooltip-position="left" @click="close">
        <PIcon name="close" :size="14" />
      </PIconButton>
    </header>

    <div class="p-finding-inspector__tabs">
      <button
        v-for="t in TABS"
        :key="t.id"
        type="button"
        class="p-finding-inspector__tab"
        :class="{ 'is-active': tab === t.id }"
        @click="tab = t.id"
      >
        {{ t.label }}
      </button>
    </div>

    <div class="p-finding-inspector__body">
      <template v-if="tab === 'overview'">
        <div class="p-finding-inspector__stats">
          <PKeyValue label="Severity" :value="findings.inspected.severity" />
          <PKeyValue label="CVSS" :value="findings.inspected.cvss_score" divider />
          <PKeyValue label="CWE" :value="findings.inspected.cwe_id ?? '—'" />
          <PKeyValue label="Status" :value="findings.inspected.status.replace('_', ' ').toLowerCase()" divider />
        </div>

        <div class="p-finding-inspector__block">
          <div class="label">Description</div>
          <p class="p-finding-inspector__prose">{{ findings.inspected.description }}</p>
        </div>

        <div class="p-finding-inspector__block">
          <div class="label">Affected URL</div>
          <PCodeBlock>{{ findings.inspected.affected_url }}</PCodeBlock>
        </div>

        <div v-if="findings.inspected.affected_parameter" class="p-finding-inspector__block">
          <div class="label">Parameter</div>
          <code class="p-finding-inspector__param">{{ findings.inspected.affected_parameter }}</code>
        </div>

        <div class="p-finding-inspector__block">
          <div class="label">Detected by</div>
          <div class="p-finding-inspector__signature">
            <PIcon name="signature" :size="14" />
            <span class="p-finding-inspector__sig-id">{{ findings.inspected.signature_id }}</span>
            <span class="p-finding-inspector__spacer" />
            <button type="button" class="p-finding-inspector__view-template">
              view template <PIcon name="arrow-right" :size="10" />
            </button>
          </div>
        </div>
      </template>

      <template v-if="tab === 'evidence'">
        <div class="label">Side-by-side evidence</div>
        <div class="p-finding-inspector__evidence">
          <PEvidencePane title="Request" tone="request" :body="REQUEST_BODY" />
          <PEvidencePane
            title="Response"
            tone="response"
            :body="RESPONSE_BODY"
            :highlight="['PostgreSQL ERROR', 'SQL syntax', 'AKIA']"
          />
        </div>
        <div class="p-finding-inspector__block">
          <div class="label">Reproduction</div>
          <PCodeBlock multiline>{{ findings.inspected.poc }}</PCodeBlock>
        </div>
        <div class="p-finding-inspector__block">
          <div class="label">Extracted</div>
          <div class="p-finding-inspector__extract">
            <span class="p-finding-inspector__extract-key">error_message</span> =
            <span class="p-finding-inspector__extract-val">"PostgreSQL ERROR: unterminated quoted string..."</span>
          </div>
        </div>
      </template>

      <template v-if="tab === 'remediation'">
        <div class="p-finding-inspector__block">
          <div class="label">Suggested fix</div>
          <p class="p-finding-inspector__prose">{{ findings.inspected.remediation }}</p>
        </div>
        <div class="p-finding-inspector__block">
          <div class="label">References</div>
          <a
            v-for="(r, i) in REFERENCES"
            :key="i"
            href="#"
            class="p-finding-inspector__ref"
          >
            <PIcon name="external" :size="11" />
            <span class="p-finding-inspector__ref-label">{{ r[0] }}</span>
            <span class="p-finding-inspector__ref-url">{{ r[1] }}</span>
          </a>
        </div>
      </template>

      <template v-if="tab === 'history'">
        <ol class="p-finding-inspector__timeline">
          <li v-for="(e, i) in TIMELINE" :key="i" class="p-finding-inspector__t-row">
            <span class="p-finding-inspector__t-when">{{ e.when }}</span>
            <span class="p-finding-inspector__t-dot" />
            <div class="p-finding-inspector__t-body">
              <div class="p-finding-inspector__t-text">{{ e.text }}</div>
              <div class="p-finding-inspector__t-who">{{ e.who }}</div>
            </div>
          </li>
        </ol>
      </template>
    </div>

    <footer class="p-finding-inspector__foot">
      <PButton variant="ghost">
        <template #icon><PIcon name="check" :size="12" /></template>
        Validate
      </PButton>
      <PButton variant="ghost">
        <template #icon><PIcon name="refresh" :size="12" /></template>
        Re-test
      </PButton>
      <span class="p-finding-inspector__spacer" />
      <PButton variant="primary">
        <template #icon><PIcon name="external" :size="12" /></template>
        Report
      </PButton>
    </footer>
    </aside>
  </Transition>
</template>

<style scoped>
.p-finding-inspector {
  width: 520px;
  flex-shrink: 0;
  background: var(--surface);
  border-radius: var(--r-3);
  box-shadow: var(--shadow-2);
  margin: 6px 0 0 6px;
  display: flex;
  flex-direction: column;
  min-height: 0;
}

.p-finding-inspector-enter-active,
.p-finding-inspector-leave-active {
  transition:
    transform var(--dur-slow) var(--ease-out),
    opacity var(--dur-slow) var(--ease-out),
    margin var(--dur-slow) var(--ease-out);
}

.p-finding-inspector-enter-from,
.p-finding-inspector-leave-to {
  opacity: 0;
  transform: translateX(16px);
  margin-right: -32px;
}

.p-finding-inspector__head {
  padding: 14px 16px;
  border-bottom: 1px solid var(--line);
  display: flex;
  align-items: flex-start;
  gap: 10px;
}

.p-finding-inspector__head-body {
  flex: 1;
  min-width: 0;
}

.p-finding-inspector__title {
  font-family: var(--font-display);
  font-size: 16px;
  font-weight: 500;
  color: var(--fg);
  line-height: 1.3;
  margin-bottom: 6px;
}

.p-finding-inspector__meta {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  font-size: var(--t-xs);
  color: var(--fg-subtle);
}

.p-finding-inspector__cwe,
.p-finding-inspector__cvss {
  font-family: var(--font-mono);
}

.p-finding-inspector__tabs {
  display: flex;
  border-bottom: 1px solid var(--line);
  padding: 0 16px;
  flex-shrink: 0;
}

.p-finding-inspector__tab {
  padding: 8px 10px;
  font-size: var(--t-sm);
  font-weight: 500;
  color: var(--fg-subtle);
  border-bottom: 1.5px solid transparent;
  margin-bottom: -1px;
  transition: color var(--dur-fast) var(--ease);
}

.p-finding-inspector__tab:hover {
  color: var(--fg);
}

.p-finding-inspector__tab.is-active {
  color: var(--fg);
  border-bottom-color: var(--fg);
}

.p-finding-inspector__body {
  flex: 1;
  overflow-y: auto;
  padding: 14px 16px;
  display: grid;
  gap: 18px;
}

.p-finding-inspector__stats {
  display: grid;
  grid-template-columns: 1fr 1fr;
  border-top: 1px solid var(--line);
  border-bottom: 1px solid var(--line);
}

.p-finding-inspector__block {
  display: grid;
  gap: 6px;
}

.p-finding-inspector__prose {
  font-size: 14px;
  line-height: 1.6;
  color: var(--fg);
  margin: 0;
}

.p-finding-inspector__param {
  display: inline-block;
  padding: 4px 8px;
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--accent);
  background: var(--accent-soft);
  border: 1px solid var(--line);
  border-radius: var(--r-1);
}

.p-finding-inspector__signature {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 10px;
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: var(--r-2);
  color: var(--fg-muted);
}

.p-finding-inspector__sig-id {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--fg);
}

.p-finding-inspector__spacer {
  flex: 1;
}

.p-finding-inspector__view-template {
  font-size: var(--t-xs);
  color: var(--accent);
  display: inline-flex;
  align-items: center;
  gap: 3px;
}

.p-finding-inspector__evidence {
  display: grid;
  gap: 10px;
}

.p-finding-inspector__extract {
  font-family: var(--font-mono);
  font-size: 11px;
  padding: 8px 10px;
  background: var(--bg-sunken);
  border: 1px solid var(--line);
  border-radius: var(--r-2);
  color: var(--fg);
}

.p-finding-inspector__extract-key {
  color: var(--accent);
}

.p-finding-inspector__extract-val {
  color: var(--ok);
}

.p-finding-inspector__ref {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 0;
  border-bottom: 1px solid var(--line-soft);
  font-size: var(--t-sm);
  color: var(--fg);
}

.p-finding-inspector__ref-label {
  flex: 1;
}

.p-finding-inspector__ref-url {
  font-family: var(--font-mono);
  font-size: var(--t-xs);
  color: var(--fg-subtle);
}

.p-finding-inspector__timeline {
  margin: 0;
  padding: 0;
  list-style: none;
}

.p-finding-inspector__t-row {
  display: flex;
  gap: 14px;
  padding: 12px 0;
  border-bottom: 1px solid var(--line-soft);
}

.p-finding-inspector__t-when {
  width: 60px;
  font-size: var(--t-xs);
  color: var(--fg-faint);
  font-family: var(--font-mono);
  flex-shrink: 0;
  padding-top: 2px;
}

.p-finding-inspector__t-dot {
  width: 4px;
  height: 4px;
  background: var(--fg-subtle);
  border-radius: 999px;
  margin-top: 7px;
  flex-shrink: 0;
}

.p-finding-inspector__t-body {
  flex: 1;
  min-width: 0;
}

.p-finding-inspector__t-text {
  font-size: var(--t-sm);
  color: var(--fg);
}

.p-finding-inspector__t-who {
  font-size: var(--t-xs);
  color: var(--fg-faint);
  margin-top: 2px;
  font-family: var(--font-mono);
}

.p-finding-inspector__foot {
  display: flex;
  gap: 6px;
  padding: 10px 16px;
  border-top: 1px solid var(--line);
  background: var(--bg);
}
</style>

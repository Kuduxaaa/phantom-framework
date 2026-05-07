<script setup lang="ts">
/**
 * Signatures view — template catalog + active signature with Builder/Source/etc tabs.
 */
import { computed, ref } from 'vue'
import PSecondaryNav from '@/components/organisms/PSecondaryNav.vue'
import PMainPanel from '@/components/organisms/PMainPanel.vue'
import PVisualBuilder from '@/components/organisms/PVisualBuilder.vue'
import PYamlEditor from '@/components/organisms/PYamlEditor.vue'
import PNavRow from '@/components/molecules/PNavRow.vue'
import PPanelHeader from '@/components/molecules/PPanelHeader.vue'
import type { PanelTab } from '@/components/molecules/PPanelHeader.vue'
import PSeverityBadge from '@/components/atoms/PSeverityBadge.vue'
import PIcon from '@/components/atoms/PIcon.vue'
import PIconButton from '@/components/atoms/PIconButton.vue'
import PButton from '@/components/atoms/PButton.vue'
import PNewSignatureModal from '@/components/organisms/PNewSignatureModal.vue'
import { useTemplatesStore } from '@/stores/templates'

type SigTab = 'visual' | 'source' | 'matchers' | 'extractors' | 'history'

const templates = useTemplatesStore()
const tab = ref<SigTab>('visual')
const newSigOpen = ref<boolean>(false)

const CATEGORIES = ['injection', 'exposure', 'authentication', 'misconfiguration', 'redirect', 'ssrf'] as const

const tabs = computed<PanelTab[]>(() => [
  { id: 'visual', label: 'Builder' },
  { id: 'source', label: 'Source' },
  { id: 'matchers', label: 'Matchers', count: 2 },
  { id: 'extractors', label: 'Extractors', count: 1 },
  { id: 'history', label: 'History' },
])

const successRate = computed<string>(() => {
  const t = templates.active
  if (!t || !t.execution_count) return '0.0'
  return ((t.success_count / t.execution_count) * 100).toFixed(1)
})

const HISTORY = [
  { v: '1.4', when: '3 days ago', who: 'kuduxaaa', msg: 'Add PostgreSQL error patterns; reject Adminer pages.' },
  { v: '1.3', when: '2 weeks ago', who: 'kuduxaaa', msg: 'Add Oracle ORA-NNNNN pattern.' },
  { v: '1.2', when: '1 month ago', who: 'phantom-team', msg: 'Switch to batteringram with multiple payloads.' },
  { v: '1.1', when: '2 months ago', who: 'phantom-team', msg: 'Add CVSS metadata.' },
  { v: '1.0', when: '3 months ago', who: 'phantom-team', msg: 'Initial release.' },
] as const

const MATCHER_REGEXES = ['SQL syntax.*MySQL', 'Warning.*mysqli?', 'PostgreSQL.*ERROR', 'ORA-[0-9]{5}'] as const
const EXTRACTOR_REGEXES = ['(SQL syntax[^<]+)', '(PostgreSQL ERROR[^<]+)'] as const
</script>

<template>
  <PSecondaryNav
    title="Signatures"
    :footer="`${templates.items.length} templates · ${templates.items.filter(t => t.is_active).length} active`"
  >
    <template #action>
      <PIconButton tooltip="New signature" shortcut="N" @click="newSigOpen = true">
        <PIcon name="plus" :size="14" />
      </PIconButton>
    </template>

    <div v-for="cat in CATEGORIES" :key="cat" class="p-sigs__group">
      <template v-if="(templates.grouped[cat] || []).length">
        <div class="label p-sigs__cat">{{ cat }}</div>
        <PNavRow
          v-for="t in templates.grouped[cat]"
          :key="t.id"
          :active="t.id === templates.activeId"
          :label="t.name"
          :sub="t.signature_id"
          @click="templates.setActive(t.id)"
        >
          <template #leading>
            <span
              class="p-sigs__sev-dot"
              :style="{ background: `var(--sev-${t.severity.toLowerCase()})` }"
            />
          </template>
          <template v-if="!t.is_active" #trailing>
            <span class="p-sigs__off">off</span>
          </template>
        </PNavRow>
      </template>
    </div>
  </PSecondaryNav>

  <PMainPanel>
    <template v-if="templates.active">
      <PPanelHeader
        :breadcrumb="[
          { label: 'Signatures' },
          { label: templates.active.category },
          { label: templates.active.signature_id },
        ]"
        :title="templates.active.name"
        :tabs="tabs"
        :active-tab="tab"
        @tab="(id: string) => (tab = id as SigTab)"
      >
        <template #subtitle>
          <span class="p-sigs__subtitle">
            <PSeverityBadge :level="templates.active.severity" variant="dot" />
            <span class="p-sigs__sep">·</span>
            <span class="p-sigs__mono">v{{ templates.active.version }}</span>
            <span class="p-sigs__sep">·</span>
            <span>by {{ templates.active.author }}</span>
            <span class="p-sigs__sep">·</span>
            <span class="tabular">
              {{ templates.active.execution_count.toLocaleString() }} executions ·
              {{ successRate }}% success
            </span>
          </span>
        </template>
        <template #actions>
          <PButton variant="ghost"><template #icon><PIcon name="eye" :size="12" /></template>Preview</PButton>
          <PButton variant="ghost"><template #icon><PIcon name="play" :size="12" /></template>Test run</PButton>
          <PButton variant="primary"><template #icon><PIcon name="check" :size="12" /></template>Save</PButton>
        </template>
      </PPanelHeader>

      <PVisualBuilder v-if="tab === 'visual'" :template="templates.active" />
      <PYamlEditor v-else-if="tab === 'source'" :source="templates.yaml" />

      <div v-else-if="tab === 'matchers'" class="p-sigs__pane">
        <div class="p-sigs__pane-inner">
          <div class="label">Matcher condition: AND — all matchers must pass</div>
          <article class="p-sigs__matcher">
            <header class="p-sigs__matcher-head">
              <span class="p-sigs__idx">1</span>
              <span class="p-sigs__type">word</span>
              <span class="p-sigs__neg">negative</span>
              <span class="p-sigs__matcher-title">Reject if 'Adminer' present (false-positive guard)</span>
              <span class="p-sigs__part">part: body</span>
            </header>
            <div class="p-sigs__matcher-body">
              <div class="p-sigs__pattern"><span class="p-sigs__pattern-idx">1</span><span class="p-sigs__word">"Adminer"</span></div>
            </div>
          </article>
          <article class="p-sigs__matcher">
            <header class="p-sigs__matcher-head">
              <span class="p-sigs__idx">2</span>
              <span class="p-sigs__type">regex</span>
              <span class="p-sigs__matcher-title">Match SQL error patterns</span>
              <span class="p-sigs__part">part: body</span>
              <span class="p-sigs__cond">OR</span>
            </header>
            <div class="p-sigs__matcher-body">
              <div v-for="(r, i) in MATCHER_REGEXES" :key="r" class="p-sigs__pattern">
                <span class="p-sigs__pattern-idx">{{ i + 1 }}</span>
                <span class="p-sigs__regex">/{{ r }}/</span>
              </div>
            </div>
          </article>
        </div>
      </div>

      <div v-else-if="tab === 'extractors'" class="p-sigs__pane">
        <div class="p-sigs__pane-inner">
          <article class="p-sigs__matcher">
            <header class="p-sigs__matcher-head">
              <span class="p-sigs__idx">1</span>
              <span class="p-sigs__type">regex</span>
              <span class="p-sigs__matcher-title">error_message — capture group 1</span>
              <span class="p-sigs__part">part: body</span>
              <span class="p-sigs__cond">GROUP 1</span>
            </header>
            <div class="p-sigs__matcher-body">
              <div v-for="(r, i) in EXTRACTOR_REGEXES" :key="r" class="p-sigs__pattern">
                <span class="p-sigs__pattern-idx">{{ i + 1 }}</span>
                <span class="p-sigs__regex">/{{ r }}/</span>
              </div>
            </div>
          </article>
          <div>
            <div class="label p-sigs__last-label">Last extracted</div>
            <pre class="p-sigs__last">error_message = "PostgreSQL ERROR: unterminated quoted string at or near \"1''\""</pre>
          </div>
        </div>
      </div>

      <div v-else-if="tab === 'history'" class="p-sigs__pane">
        <div class="p-sigs__pane-inner">
          <ol class="p-sigs__history">
            <li v-for="h in HISTORY" :key="h.v" class="p-sigs__history-row">
              <span class="p-sigs__h-v">v{{ h.v }}</span>
              <span class="p-sigs__h-when">{{ h.when }}</span>
              <span class="p-sigs__h-who">{{ h.who }}</span>
              <span class="p-sigs__h-msg">{{ h.msg }}</span>
            </li>
          </ol>
        </div>
      </div>
    </template>
  </PMainPanel>

  <PNewSignatureModal v-model:open="newSigOpen" />
</template>

<style scoped>
.p-sigs__group {
  margin-bottom: 8px;
}

.p-sigs__cat {
  padding: 6px 8px 4px;
}

.p-sigs__sev-dot {
  width: 8px;
  height: 8px;
  border-radius: 2px;
  display: inline-block;
}

.p-sigs__off {
  font-size: 9px;
  color: var(--fg-faint);
  text-transform: uppercase;
  letter-spacing: var(--tracking-label);
}

.p-sigs__subtitle {
  display: inline-flex;
  align-items: center;
  gap: 10px;
}

.p-sigs__sep {
  color: var(--fg-faint);
}

.p-sigs__mono {
  font-family: var(--font-mono);
}

.p-sigs__pane {
  flex: 1;
  overflow-y: auto;
  padding: var(--s-8) var(--s-10);
}

.p-sigs__pane-inner {
  max-width: 900px;
  display: grid;
  gap: var(--s-7);
}

.p-sigs__matcher {
  border: 1px solid var(--line);
  border-radius: var(--r-3);
  background: var(--surface);
  overflow: hidden;
}

.p-sigs__matcher-head {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  border-bottom: 1px solid var(--line);
  background: var(--bg-elev);
}

.p-sigs__idx {
  width: 22px;
  height: 22px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 600;
  color: var(--fg-muted);
  background: var(--bg);
  border: 1px solid var(--line);
  border-radius: var(--r-1);
}

.p-sigs__type {
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: var(--tracking-label);
  color: var(--fg-subtle);
  font-family: var(--font-mono);
}

.p-sigs__neg {
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: var(--tracking-label);
  color: var(--err);
  font-family: var(--font-mono);
}

.p-sigs__matcher-title {
  font-size: var(--t-sm);
  color: var(--fg);
  flex: 1;
}

.p-sigs__part {
  font-size: var(--t-xs);
  color: var(--fg-subtle);
  font-family: var(--font-mono);
}

.p-sigs__cond {
  font-size: var(--t-xs);
  color: var(--fg-subtle);
  font-family: var(--font-mono);
}

.p-sigs__matcher-body {
  padding: 8px 14px;
  font-family: var(--font-mono);
  font-size: 12px;
}

.p-sigs__pattern {
  padding: 4px 0;
  color: var(--fg);
  border-bottom: 1px solid var(--line-soft);
}

.p-sigs__pattern:last-child {
  border-bottom: none;
}

.p-sigs__pattern-idx {
  color: var(--fg-faint);
  margin-right: 8px;
}

.p-sigs__word {
  color: var(--ok);
}

.p-sigs__regex {
  color: var(--accent);
}

.p-sigs__last-label {
  margin-bottom: 12px;
}

.p-sigs__last {
  margin: 0;
  padding: 14px;
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--fg);
  background: var(--bg-sunken);
  border: 1px solid var(--line);
  border-radius: var(--r-2);
  white-space: pre-wrap;
}

.p-sigs__history {
  margin: 0;
  padding: 0;
  list-style: none;
}

.p-sigs__history-row {
  display: grid;
  grid-template-columns: 60px 100px 100px 1fr;
  gap: 16px;
  padding: 12px 0;
  border-bottom: 1px solid var(--line);
}

.p-sigs__h-v {
  font-family: var(--font-mono);
  color: var(--accent);
  font-weight: 500;
}

.p-sigs__h-when {
  font-size: var(--t-sm);
  color: var(--fg-subtle);
}

.p-sigs__h-who {
  font-family: var(--font-mono);
  font-size: var(--t-xs);
  color: var(--fg-muted);
}

.p-sigs__h-msg {
  font-size: var(--t-sm);
  color: var(--fg);
}
</style>

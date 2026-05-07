<script setup lang="ts">
/**
 * Visual signature builder — vertical, three-step composition.
 *
 *   1. Request   — method, URL, attack mode, payloads, headers
 *   2. Matchers  — list of matcher cards combined with AND / OR
 *   3. Output    — extractor + finding emit (title, severity, tags)
 *
 * All controls are real (selects, inputs, editable lists). Local state is
 * scoped to the builder; saving back to a real signature is left to a
 * downstream "Save" handler.
 */
import { computed, ref, watch } from 'vue'
import PBuilderStep from '../molecules/PBuilderStep.vue'
import PEditableList from '../molecules/PEditableList.vue'
import PFormField from '../atoms/PFormField.vue'
import PInput from '../atoms/PInput.vue'
import PSelect from '../atoms/PSelect.vue'
import PToggle from '../atoms/PToggle.vue'
import PButton from '../atoms/PButton.vue'
import PIcon from '../atoms/PIcon.vue'
import PSeverityBadge from '../atoms/PSeverityBadge.vue'
import type { Severity, SignatureTemplate } from '@/types'

interface Props {
  template: SignatureTemplate
}

const props = defineProps<Props>()

type MatcherType = 'word' | 'regex' | 'status' | 'size'
type MatcherPart = 'body' | 'headers' | 'all'
type MatcherCondition = 'and' | 'or'

interface Matcher {
  id: number
  type: MatcherType
  title: string
  patterns: string[]
  negative: boolean
  part: MatcherPart
  condition: MatcherCondition
}

const reqMethod = ref<string>('GET')
const urlPath = ref<string>('{{BaseURL}}/?id=1{{payload}}')
const attack = ref<string>('batteringram')
const payloads = ref<string[]>(["' OR 1=1--", "1' AND SLEEP(5)--", '1" UNION SELECT NULL--'])
const headers = ref<Array<{ key: string; value: string }>>([
  { key: 'User-Agent', value: 'Phantom/1.0' },
  { key: 'Accept', value: '*/*' },
])
const stopAtFirst = ref<boolean>(true)

const logic = ref<'and' | 'or'>('and')
const matchers = ref<Matcher[]>([
  {
    id: 1,
    type: 'word',
    title: 'Reject Adminer pages',
    patterns: ['Adminer'],
    negative: true,
    part: 'body',
    condition: 'and',
  },
  {
    id: 2,
    type: 'regex',
    title: 'SQL error patterns',
    patterns: ['SQL syntax.*MySQL', 'Warning.*mysqli?', 'PostgreSQL.*ERROR', 'ORA-[0-9]{5}'],
    negative: false,
    part: 'body',
    condition: 'or',
  },
])

const extractorName = ref<string>('error_message')
const extractorPatterns = ref<string[]>(['(SQL syntax[^<]+)', '(PostgreSQL ERROR[^<]+)'])

const findingTitle = ref<string>('SQL Injection at {{matched_url}}')
const findingSeverity = ref<Lowercase<Severity>>('critical')
const findingTags = ref<string[]>(['sqli', 'injection', 'owasp-a03', 'cwe-89'])
const cvss = ref<string>('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')

watch(
  () => props.template.severity,
  (v) => {
    findingSeverity.value = v
  },
  { immediate: true },
)

const METHOD_OPTIONS = [
  { value: 'GET', label: 'GET' },
  { value: 'POST', label: 'POST' },
  { value: 'PUT', label: 'PUT' },
  { value: 'DELETE', label: 'DELETE' },
  { value: 'PATCH', label: 'PATCH' },
]

const ATTACK_OPTIONS = [
  { value: 'batteringram', label: 'Batteringram (single payload set)' },
  { value: 'pitchfork', label: 'Pitchfork (parallel sets)' },
  { value: 'clusterbomb', label: 'Clusterbomb (cartesian product)' },
]

const TYPE_OPTIONS: Array<{ value: MatcherType; label: string }> = [
  { value: 'word', label: 'Word match' },
  { value: 'regex', label: 'Regex' },
  { value: 'status', label: 'Status code' },
  { value: 'size', label: 'Body size' },
]

const PART_OPTIONS: Array<{ value: MatcherPart; label: string }> = [
  { value: 'body', label: 'Response body' },
  { value: 'headers', label: 'Response headers' },
  { value: 'all', label: 'All' },
]

const SEVERITY_OPTIONS = [
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'info', label: 'Info' },
]

const tagDraft = ref<string>('')

function addHeader(): void {
  headers.value.push({ key: '', value: '' })
}

function removeHeader(idx: number): void {
  headers.value.splice(idx, 1)
}

function addMatcher(): void {
  const id = Math.max(0, ...matchers.value.map((m) => m.id)) + 1
  matchers.value.push({
    id,
    type: 'regex',
    title: 'New matcher',
    patterns: [],
    negative: false,
    part: 'body',
    condition: 'or',
  })
}

function removeMatcher(id: number): void {
  matchers.value = matchers.value.filter((m) => m.id !== id)
}

function commitTag(): void {
  const v = tagDraft.value.trim()
  if (!v || findingTags.value.includes(v)) return
  findingTags.value = [...findingTags.value, v]
  tagDraft.value = ''
}

function removeTag(tag: string): void {
  findingTags.value = findingTags.value.filter((t) => t !== tag)
}

const requestSummary = computed<string>(
  () => `${reqMethod.value} ${urlPath.value.length > 50 ? urlPath.value.slice(0, 47) + '…' : urlPath.value}`,
)

const matcherSummary = computed<string>(
  () => `${matchers.value.length} matcher${matchers.value.length === 1 ? '' : 's'} combined with ${logic.value.toUpperCase()}`,
)

const outputSummary = computed<string>(
  () => `Emit ${findingSeverity.value} finding · ${findingTags.value.length} tag${findingTags.value.length === 1 ? '' : 's'}`,
)
</script>

<template>
  <div class="p-vb">
    <div class="p-vb__inner">
      <PBuilderStep :step="1" title="Request" :caption="requestSummary">
        <div class="p-vb__row p-vb__row--method">
          <PFormField label="Method">
            <PSelect v-model="reqMethod" :options="METHOD_OPTIONS" size="sm" />
          </PFormField>
          <PFormField label="Path template" hint="Variables like {{BaseURL}} and {{payload}} are substituted at scan time.">
            <PInput v-model="urlPath" mono size="sm" placeholder="{{BaseURL}}/path?param={{payload}}" />
          </PFormField>
        </div>

        <PFormField label="Attack mode">
          <PSelect v-model="attack" :options="ATTACK_OPTIONS" size="sm" />
        </PFormField>

        <PFormField label="Payloads">
          <template #action>
            <span class="p-vb__hint">{{ payloads.length }} value{{ payloads.length === 1 ? '' : 's' }}</span>
          </template>
          <PEditableList
            v-model="payloads"
            kind="plain"
            placeholder="New payload, e.g. ' OR 1=1--"
            add-label="payload"
          />
        </PFormField>

        <PFormField label="Headers">
          <template #action>
            <button type="button" class="p-vb__inline-btn" @click="addHeader">
              <PIcon name="plus" :size="11" /> Add header
            </button>
          </template>
          <div class="p-vb__headers">
            <div v-for="(h, i) in headers" :key="i" class="p-vb__header-row">
              <input
                v-model="h.key"
                class="p-vb__header-input p-vb__header-input--key"
                placeholder="Header"
              />
              <input
                v-model="h.value"
                class="p-vb__header-input p-vb__header-input--value"
                placeholder="Value"
              />
              <button
                type="button"
                class="p-vb__header-x"
                title="Remove header"
                @click="removeHeader(i)"
              ><PIcon name="close" :size="11" /></button>
            </div>
            <div v-if="!headers.length" class="p-vb__empty-line">No headers configured.</div>
          </div>
        </PFormField>

        <div class="p-vb__inline-toggle">
          <PToggle v-model="stopAtFirst" />
          <span class="p-vb__inline-toggle-label">Stop at first match</span>
          <span class="p-vb__inline-toggle-hint">Skip remaining payloads after the first hit per matcher.</span>
        </div>
      </PBuilderStep>

      <PBuilderStep :step="2" title="Matchers" :caption="matcherSummary">
        <template #action>
          <div class="p-vb__logic">
            <button
              v-for="op in (['and', 'or'] as const)"
              :key="op"
              type="button"
              class="p-vb__logic-btn"
              :class="{ 'is-active': logic === op }"
              @click="logic = op"
            >{{ op.toUpperCase() }}</button>
          </div>
        </template>

        <div class="p-vb__matchers">
          <article
            v-for="m in matchers"
            :key="m.id"
            class="p-vb__matcher"
            :class="{ 'is-negative': m.negative }"
          >
            <header class="p-vb__matcher-head">
              <input v-model="m.title" class="p-vb__matcher-title" placeholder="Untitled matcher" />
              <button
                type="button"
                class="p-vb__matcher-x"
                title="Remove matcher"
                @click="removeMatcher(m.id)"
              ><PIcon name="close" :size="11" /></button>
            </header>

            <div class="p-vb__matcher-config">
              <PFormField label="Type">
                <PSelect v-model="m.type" :options="TYPE_OPTIONS" size="sm" />
              </PFormField>
              <PFormField label="Match against">
                <PSelect v-model="m.part" :options="PART_OPTIONS" size="sm" />
              </PFormField>
              <div class="p-vb__neg-toggle">
                <PToggle v-model="m.negative" />
                <span>Negative (reject if matches)</span>
              </div>
            </div>

            <PFormField :label="m.type === 'word' ? 'Words' : m.type === 'regex' ? 'Patterns' : 'Values'">
              <PEditableList
                v-model="m.patterns"
                :kind="m.type === 'word' ? 'word' : m.type === 'regex' ? 'regex' : 'plain'"
                :placeholder="m.type === 'regex' ? 'New regex pattern' : 'New value'"
                :add-label="m.type"
              />
            </PFormField>
          </article>

          <button type="button" class="p-vb__add-matcher" @click="addMatcher">
            <PIcon name="plus" :size="12" /> Add matcher
          </button>
        </div>
      </PBuilderStep>

      <PBuilderStep :step="3" title="Output" :caption="outputSummary" :connector="false">
        <PFormField label="Extractor name" hint="Captured value name. Available later in finding templates as {{name}}.">
          <PInput v-model="extractorName" mono size="sm" placeholder="e.g. error_message" />
        </PFormField>

        <PFormField label="Extractor patterns">
          <PEditableList
            v-model="extractorPatterns"
            kind="regex"
            placeholder="Regex with capture group: (foo[^<]+)"
            add-label="pattern"
          />
        </PFormField>

        <div class="p-vb__divider" />

        <PFormField label="Finding title template">
          <PInput v-model="findingTitle" placeholder="e.g. SQL Injection at {{matched_url}}" />
        </PFormField>

        <div class="p-vb__row">
          <PFormField label="Severity">
            <PSelect v-model="findingSeverity" :options="SEVERITY_OPTIONS" size="sm" />
          </PFormField>
          <PFormField label="Severity preview">
            <div class="p-vb__sev-preview">
              <PSeverityBadge :level="findingSeverity" />
            </div>
          </PFormField>
        </div>

        <PFormField label="Tags">
          <div class="p-vb__tags">
            <span v-for="t in findingTags" :key="t" class="p-vb__tag">
              {{ t }}
              <button type="button" class="p-vb__tag-x" @click="removeTag(t)">
                <PIcon name="close" :size="9" />
              </button>
            </span>
            <form class="p-vb__tag-add" @submit.prevent="commitTag">
              <input v-model="tagDraft" placeholder="Add tag…" class="p-vb__tag-input" />
            </form>
          </div>
        </PFormField>

        <PFormField label="CVSS vector" hint="Optional. Used to score the resulting findings.">
          <PInput v-model="cvss" mono size="sm" placeholder="CVSS:3.1/…" />
        </PFormField>

        <div class="p-vb__footer">
          <PButton variant="ghost">
            <template #icon><PIcon name="play" :size="12" /></template>
            Test against capture
          </PButton>
          <span class="p-vb__spacer" />
          <PButton variant="accent">
            <template #icon><PIcon name="check" :size="12" /></template>
            Save signature
          </PButton>
        </div>
      </PBuilderStep>
    </div>
  </div>
</template>

<style scoped>
.p-vb {
  flex: 1;
  overflow: auto;
  background: var(--bg);
}

.p-vb__inner {
  max-width: 760px;
  margin: 0 auto;
  padding: var(--s-9) var(--s-8);
  display: flex;
  flex-direction: column;
}

.p-vb__row {
  display: grid;
  grid-template-columns: 180px 1fr;
  gap: 16px;
  align-items: start;
}

.p-vb__row--method {
  grid-template-columns: 140px 1fr;
}

.p-vb__hint {
  font-size: var(--t-xs);
  color: var(--fg-subtle);
  font-family: var(--font-mono);
}

.p-vb__inline-btn {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 11px;
  font-weight: 500;
  color: var(--accent);
  padding: 2px 6px;
  border-radius: var(--r-1);
}

.p-vb__inline-btn:hover {
  background: var(--accent-soft);
}

.p-vb__headers {
  display: grid;
  gap: 4px;
}

.p-vb__header-row {
  display: grid;
  grid-template-columns: 160px 1fr auto;
  gap: 4px;
  align-items: center;
}

.p-vb__header-input {
  background: var(--bg-sunken);
  border: 1px solid var(--line-soft);
  border-radius: var(--r-1);
  padding: 5px 8px;
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--fg);
  outline: none;
  transition:
    border-color var(--dur-fast) var(--ease),
    box-shadow var(--dur-fast) var(--ease);
}

.p-vb__header-input:hover {
  border-color: var(--line-strong);
}

.p-vb__header-input:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 2px var(--accent-soft);
}

.p-vb__header-input--key {
  color: var(--fg-muted);
}

.p-vb__header-x {
  color: var(--fg-subtle);
  padding: 4px;
  border-radius: var(--r-1);
}

.p-vb__header-x:hover {
  color: var(--err);
  background: var(--hover);
}

.p-vb__empty-line {
  font-size: 11px;
  color: var(--fg-faint);
  font-style: italic;
  padding: 6px 0;
}

.p-vb__inline-toggle {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 12px;
  background: var(--bg-elev);
  border: 1px solid var(--line);
  border-radius: var(--r-2);
}

.p-vb__inline-toggle-label {
  font-size: var(--t-sm);
  color: var(--fg);
  font-weight: 500;
}

.p-vb__inline-toggle-hint {
  flex: 1;
  font-size: var(--t-xs);
  color: var(--fg-subtle);
}

.p-vb__logic {
  display: inline-flex;
  border: 1px solid var(--line-strong);
  border-radius: var(--r-1);
  overflow: hidden;
}

.p-vb__logic-btn {
  padding: 4px 10px;
  font-size: 10.5px;
  font-weight: 600;
  font-family: var(--font-mono);
  letter-spacing: var(--tracking-label);
  color: var(--fg-subtle);
  background: var(--surface);
  transition:
    background var(--dur-fast) var(--ease),
    color var(--dur-fast) var(--ease);
}

.p-vb__logic-btn:hover {
  color: var(--fg);
}

.p-vb__logic-btn.is-active {
  background: var(--accent-soft);
  color: var(--accent);
}

.p-vb__matchers {
  display: grid;
  gap: 12px;
}

.p-vb__matcher {
  background: var(--bg-elev);
  border: 1px solid var(--line);
  border-radius: var(--r-2);
  border-left-width: 3px;
  border-left-color: var(--sev-medium);
  padding: 12px 14px;
  display: grid;
  gap: 12px;
  transition: border-color var(--dur-fast) var(--ease);
}

.p-vb__matcher.is-negative {
  border-left-color: var(--err);
}

.p-vb__matcher-head {
  display: flex;
  align-items: center;
  gap: 8px;
}

.p-vb__matcher-title {
  flex: 1;
  background: transparent;
  border: 0;
  border-bottom: 1px solid transparent;
  outline: none;
  font-size: var(--t-md);
  font-weight: 500;
  color: var(--fg);
  padding: 4px 2px;
  transition: border-color var(--dur-fast) var(--ease);
}

.p-vb__matcher-title:hover,
.p-vb__matcher-title:focus {
  border-bottom-color: var(--line-strong);
}

.p-vb__matcher-title:focus {
  border-bottom-color: var(--accent);
}

.p-vb__matcher-x {
  color: var(--fg-subtle);
  padding: 4px;
  border-radius: var(--r-1);
}

.p-vb__matcher-x:hover {
  color: var(--err);
  background: var(--hover);
}

.p-vb__matcher-config {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  align-items: end;
}

.p-vb__neg-toggle {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: var(--t-sm);
  color: var(--fg-muted);
  grid-column: 1 / -1;
}

.p-vb__add-matcher {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  width: 100%;
  padding: 10px;
  font-size: var(--t-sm);
  font-weight: 500;
  color: var(--fg-subtle);
  background: transparent;
  border: 1px dashed var(--line);
  border-radius: var(--r-2);
  transition:
    color var(--dur-fast) var(--ease),
    border-color var(--dur-fast) var(--ease),
    background var(--dur-fast) var(--ease);
}

.p-vb__add-matcher:hover {
  color: var(--fg);
  border-color: var(--accent);
  background: var(--accent-soft);
}

.p-vb__divider {
  height: 1px;
  background: var(--line);
  margin: 4px -16px;
}

.p-vb__sev-preview {
  display: flex;
  align-items: center;
  height: 28px;
}

.p-vb__tags {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;
}

.p-vb__tag {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 4px 3px 8px;
  font-size: 10.5px;
  font-family: var(--font-mono);
  color: var(--fg-muted);
  background: var(--bg-sunken);
  border: 1px solid var(--line-soft);
  border-radius: var(--r-1);
}

.p-vb__tag-x {
  display: inline-flex;
  color: var(--fg-faint);
  border-radius: var(--r-1);
  padding: 1px;
}

.p-vb__tag-x:hover {
  color: var(--err);
  background: var(--hover);
}

.p-vb__tag-add {
  display: inline-flex;
}

.p-vb__tag-input {
  background: transparent;
  border: 1px dashed var(--line);
  border-radius: var(--r-1);
  padding: 3px 8px;
  font-family: var(--font-mono);
  font-size: 10.5px;
  color: var(--fg);
  outline: none;
  width: 110px;
}

.p-vb__tag-input:focus {
  border-color: var(--accent);
  border-style: solid;
}

.p-vb__tag-input::placeholder {
  color: var(--fg-faint);
}

.p-vb__footer {
  display: flex;
  align-items: center;
  gap: 8px;
  padding-top: 6px;
  border-top: 1px solid var(--line);
  margin-top: 4px;
}

.p-vb__spacer {
  flex: 1;
}
</style>

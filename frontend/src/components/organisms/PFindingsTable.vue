<script setup lang="ts">
/**
 * Cross-target findings table — severity, title + URL, status, CWE, signature, age.
 *
 * Sorted by severity, then by descending id. Rows emit `select` on click.
 */
import { computed } from 'vue'
import PSeverityBadge from '../atoms/PSeverityBadge.vue'
import PStatusPill from '../atoms/PStatusPill.vue'
import { fmtRel } from '@/utils/time'
import type { Finding, Severity } from '@/types'

interface Props {
  findings: Finding[]
}

const props = defineProps<Props>()
const emit = defineEmits<{ select: [finding: Finding] }>()

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
}

const sorted = computed<Finding[]>(() =>
  [...props.findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.id - a.id,
  ),
)

function onSelect(finding: Finding): void {
  emit('select', finding)
}
</script>

<template>
  <div class="p-findings-table">
    <div class="p-findings-table__head">
      <span class="label p-findings-table__col-sev">Severity</span>
      <span class="label p-findings-table__col-title">Title</span>
      <span class="label p-findings-table__col-status">Status</span>
      <span class="label p-findings-table__col-cwe">CWE</span>
      <span class="label p-findings-table__col-sig">Signature</span>
      <span class="label p-findings-table__col-age">Age</span>
    </div>
    <button
      v-for="f in sorted"
      :key="f.id"
      type="button"
      class="p-findings-table__row"
      @click="onSelect(f)"
    >
      <span class="p-findings-table__col-sev">
        <PSeverityBadge :level="f.severity" />
      </span>
      <div class="p-findings-table__col-title p-findings-table__title">
        <div class="p-findings-table__title-text">{{ f.title }}</div>
        <div class="p-findings-table__title-url">{{ f.affected_url }}</div>
      </div>
      <span class="p-findings-table__col-status">
        <PStatusPill :status="f.status" />
      </span>
      <span class="p-findings-table__col-cwe p-findings-table__mono">
        {{ f.cwe_id || '—' }}
      </span>
      <span class="p-findings-table__col-sig p-findings-table__mono">
        {{ f.signature_id }}
      </span>
      <span class="p-findings-table__col-age tabular p-findings-table__age">
        {{ fmtRel(f.created_at) }}
      </span>
    </button>
  </div>
</template>

<style scoped>
.p-findings-table {
  min-width: 0;
}

.p-findings-table__head {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 8px 20px;
  border-bottom: 1px solid var(--line);
  background: var(--bg);
  position: sticky;
  top: 0;
  z-index: 1;
}

.p-findings-table__row {
  position: relative;
  display: flex;
  align-items: center;
  gap: 14px;
  width: 100%;
  padding: 11px 20px;
  border-bottom: 1px solid var(--line-soft);
  background: transparent;
  text-align: left;
  cursor: pointer;
  transition: background var(--dur-fast) var(--ease);
  min-width: 0;
}

.p-findings-table__row::before {
  content: '';
  position: absolute;
  left: 0;
  top: 0;
  bottom: 0;
  width: 2px;
  background: transparent;
  transition: background var(--dur-fast) var(--ease);
}

.p-findings-table__row:hover {
  background: var(--hover);
}

.p-findings-table__row:hover::before {
  background: var(--line-strong);
}

.p-findings-table__col-sev {
  width: 78px;
  flex-shrink: 0;
}

.p-findings-table__col-title {
  flex: 1;
  min-width: 0;
}

.p-findings-table__col-status {
  width: 110px;
  flex-shrink: 0;
}

.p-findings-table__col-cwe {
  width: 80px;
  flex-shrink: 0;
}

.p-findings-table__col-sig {
  width: 130px;
  flex-shrink: 0;
}

.p-findings-table__col-age {
  width: 60px;
  flex-shrink: 0;
}

.p-findings-table__title-text {
  font-size: var(--t-md);
  font-weight: 500;
  color: var(--fg);
  margin-bottom: 2px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  letter-spacing: var(--tracking-tight);
}

.p-findings-table__title-url {
  font-size: 11px;
  color: var(--fg-subtle);
  font-family: var(--font-mono);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.p-findings-table__mono {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--fg-subtle);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.p-findings-table__age {
  text-align: right;
  font-size: 11px;
  color: var(--fg-subtle);
}
</style>

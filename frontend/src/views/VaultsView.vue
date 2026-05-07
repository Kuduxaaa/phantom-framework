<script setup lang="ts">
/**
 * Vaults view — bug bounty program list + active vault overview.
 */
import { computed } from 'vue'
import PSecondaryNav from '@/components/organisms/PSecondaryNav.vue'
import PMainPanel from '@/components/organisms/PMainPanel.vue'
import PNavRow from '@/components/molecules/PNavRow.vue'
import PPanelHeader from '@/components/molecules/PPanelHeader.vue'
import PPlatformGlyph from '@/components/molecules/PPlatformGlyph.vue'
import PRunningPulse from '@/components/atoms/PRunningPulse.vue'
import PIconButton from '@/components/atoms/PIconButton.vue'
import PIcon from '@/components/atoms/PIcon.vue'
import PButton from '@/components/atoms/PButton.vue'
import PStat from '@/components/atoms/PStat.vue'
import PSection from '@/components/atoms/PSection.vue'
import PSeverityBadge from '@/components/atoms/PSeverityBadge.vue'
import PEmptyTorii from '@/components/atoms/PEmptyTorii.vue'
import PNewVaultModal from '@/components/organisms/PNewVaultModal.vue'
import { ref } from 'vue'
import { useVaultsStore } from '@/stores/vaults'
import { fmtRel } from '@/utils/time'
import type { Severity, Vault } from '@/types'

const vaults = useVaultsStore()
const newVaultOpen = ref<boolean>(false)

const totalFindings = computed<number>(() =>
  vaults.items.reduce((sum, v) => sum + v.stats.findings, 0),
)

const activityEvents = [
  { ts: '8m', kind: 'scan', text: 'vulnerability_scan completed on api.acme.io · 4 findings' },
  { ts: '35m', kind: 'finding', text: 'JWT "none" algorithm — critical · /v2/auth/refresh' },
  { ts: '1h', kind: 'asset', text: '12 new subdomains discovered for *.acme.com' },
  { ts: '3h', kind: 'finding', text: 'Reflected XSS validated on landing.acme.com' },
  { ts: '18h', kind: 'report', text: 'phpMyAdmin exposure reported · awaiting triage' },
  { ts: '2d', kind: 'workflow', text: 'recon-baseline workflow completed for 3 targets' },
] as const

const ACTIVITY_COLORS: Record<string, string> = {
  scan: 'var(--sev-info)',
  finding: 'var(--sev-high)',
  asset: 'var(--ok)',
  report: 'var(--accent)',
  workflow: 'var(--fg-muted)',
}

interface SeverityBar {
  sev: Lowercase<Severity>
  count: number
}

function severityBars(vault: Vault): SeverityBar[] {
  const data: SeverityBar[] = [
    { sev: 'critical', count: vault.stats.critical },
    { sev: 'high', count: vault.stats.high },
    {
      sev: 'medium',
      count: Math.max(0, vault.stats.findings - vault.stats.critical - vault.stats.high - 4),
    },
    { sev: 'low', count: 3 },
    { sev: 'info', count: 1 },
  ]
  return data
}

function maxBar(bars: SeverityBar[]): number {
  return Math.max(...bars.map((b) => b.count), 1)
}
</script>

<template>
  <PSecondaryNav
    title="Vaults"
    :footer="`${vaults.items.length} programs · ${totalFindings} findings`"
  >
    <template #action>
      <PIconButton tooltip="New vault" shortcut="N" @click="newVaultOpen = true">
        <PIcon name="plus" :size="14" />
      </PIconButton>
    </template>

    <PNavRow
      v-for="v in vaults.items"
      :key="v.id"
      :active="v.id === vaults.activeId"
      :label="v.name"
      :sub="v.target_domain"
      @click="vaults.setActive(v.id)"
    >
      <template #leading>
        <PPlatformGlyph :platform="v.platform" />
      </template>
      <template v-if="v.stats.scans_running > 0" #trailing>
        <PRunningPulse />
      </template>
    </PNavRow>
  </PSecondaryNav>

  <PMainPanel>
    <template v-if="vaults.active">
      <PPanelHeader
        :breadcrumb="[{ label: 'Vaults' }, { label: vaults.active.name }]"
        :title="vaults.active.name"
      >
        <template #subtitle>
          <span class="p-vaults__subtitle">
            <span>{{ vaults.active.target_domain }}</span>
            <span class="p-vaults__sep">·</span>
            <span class="p-vaults__platform">{{ vaults.active.platform.toLowerCase() }}</span>
            <template v-if="vaults.active.program_url">
              <span class="p-vaults__sep">·</span>
              <a href="#" class="p-vaults__link">
                program page <PIcon name="external" :size="11" />
              </a>
            </template>
          </span>
        </template>
        <template #actions>
          <PButton variant="secondary">
            <template #icon><PIcon name="scan" :size="12" /></template>
            Run scan
          </PButton>
          <PButton variant="primary">
            <template #icon><PIcon name="plus" :size="12" /></template>
            Add target
          </PButton>
        </template>
      </PPanelHeader>

      <div class="p-vaults__body">
        <div class="p-vaults__overview">
          <div class="p-vaults__stats">
            <PStat label="Targets" :value="vaults.active.stats.targets" />
            <PStat label="Findings" :value="vaults.active.stats.findings" divider />
            <PStat
              label="Critical"
              :value="vaults.active.stats.critical"
              value-color="var(--sev-critical)"
              divider
            />
            <PStat
              label="High"
              :value="vaults.active.stats.high"
              value-color="var(--sev-high)"
              divider
            />
            <PStat
              label="Last activity"
              :value="fmtRel(vaults.active.last_activity)"
              :mono="false"
              divider
            />
          </div>

          <div class="p-vaults__columns">
            <PSection title="Scope">
              <div class="p-vaults__scope">
                <div class="p-vaults__scope-block">
                  <div class="p-vaults__scope-head">
                    <span class="p-vaults__scope-dot" :style="{ background: 'var(--ok)' }" />
                    <span class="label">In scope</span>
                    <span class="p-vaults__scope-count">{{ vaults.active.scope_rules.in.length }}</span>
                  </div>
                  <div
                    v-if="vaults.active.scope_rules.in.length === 0"
                    class="p-vaults__scope-empty"
                  >none</div>
                  <div
                    v-for="rule in vaults.active.scope_rules.in"
                    :key="rule"
                    class="p-vaults__scope-rule"
                  >{{ rule }}</div>
                </div>
                <div class="p-vaults__scope-block">
                  <div class="p-vaults__scope-head">
                    <span class="p-vaults__scope-dot" :style="{ background: 'var(--err)' }" />
                    <span class="label">Out of scope</span>
                    <span class="p-vaults__scope-count">{{ vaults.active.scope_rules.out.length }}</span>
                  </div>
                  <div
                    v-if="vaults.active.scope_rules.out.length === 0"
                    class="p-vaults__scope-empty"
                  >none</div>
                  <div
                    v-for="rule in vaults.active.scope_rules.out"
                    :key="rule"
                    class="p-vaults__scope-rule"
                  >{{ rule }}</div>
                </div>
              </div>
            </PSection>

            <PSection title="Recent activity">
              <ol class="p-vaults__activity">
                <li
                  v-for="(e, i) in activityEvents"
                  :key="i"
                  class="p-vaults__activity-row"
                  :class="{ 'is-last': i === activityEvents.length - 1 }"
                >
                  <span class="tabular p-vaults__activity-ts">{{ e.ts }}</span>
                  <span class="p-vaults__activity-dot" :style="{ background: ACTIVITY_COLORS[e.kind] }" />
                  <span class="p-vaults__activity-text">{{ e.text }}</span>
                </li>
              </ol>
            </PSection>
          </div>

          <PSection title="Findings by severity">
            <div class="p-vaults__bars">
              <div
                v-for="bar in severityBars(vaults.active)"
                :key="bar.sev"
                class="p-vaults__bar-row"
              >
                <PSeverityBadge :level="bar.sev" variant="dot" />
                <div class="p-vaults__bar-track">
                  <div
                    class="p-vaults__bar-fill"
                    :style="{
                      width: `${(bar.count / maxBar(severityBars(vaults.active))) * 100}%`,
                      background: `var(--sev-${bar.sev})`,
                    }"
                  />
                </div>
                <span class="tabular p-vaults__bar-count">{{ bar.count }}</span>
              </div>
            </div>
          </PSection>
        </div>
      </div>
    </template>
    <PEmptyTorii v-else title="No vault selected" hint="Choose a program from the list to begin." />
  </PMainPanel>

  <PNewVaultModal v-model:open="newVaultOpen" />
</template>

<style scoped>
.p-vaults__subtitle {
  display: inline-flex;
  align-items: center;
  gap: 10px;
}

.p-vaults__sep {
  color: var(--fg-faint);
}

.p-vaults__platform {
  font-size: var(--t-xs);
  color: var(--fg-subtle);
  letter-spacing: 0.02em;
}

.p-vaults__link {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  color: var(--fg-muted);
}

.p-vaults__body {
  overflow-y: auto;
  flex: 1;
  padding: var(--s-8) var(--s-10);
}

.p-vaults__overview {
  display: grid;
  gap: var(--s-9);
  max-width: 1100px;
}

.p-vaults__stats {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  border-top: 1px solid var(--line);
  border-bottom: 1px solid var(--line);
}

.p-vaults__columns {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--s-9);
}

.p-vaults__scope {
  display: grid;
  gap: 14px;
}

.p-vaults__scope-head {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-bottom: 6px;
}

.p-vaults__scope-dot {
  width: 8px;
  height: 8px;
  border-radius: 999px;
}

.p-vaults__scope-count {
  font-size: var(--t-xs);
  color: var(--fg-subtle);
}

.p-vaults__scope-empty {
  font-size: var(--t-sm);
  color: var(--fg-faint);
  font-style: italic;
  padding-left: 14px;
}

.p-vaults__scope-rule {
  font-family: var(--font-mono);
  font-size: 12px;
  padding: 4px 8px 4px 14px;
  color: var(--fg);
  border-left: 1px solid var(--line);
}

.p-vaults__activity {
  margin: 0;
  padding: 0;
  list-style: none;
}

.p-vaults__activity-row {
  display: flex;
  gap: 12px;
  padding: 8px 0;
  border-bottom: 1px solid var(--line-soft);
}

.p-vaults__activity-row.is-last {
  border-bottom: none;
}

.p-vaults__activity-ts {
  width: 32px;
  font-size: var(--t-xs);
  color: var(--fg-faint);
  font-family: var(--font-mono);
  flex-shrink: 0;
  padding-top: 2px;
}

.p-vaults__activity-dot {
  width: 4px;
  height: 4px;
  border-radius: 999px;
  margin-top: 7px;
  flex-shrink: 0;
}

.p-vaults__activity-text {
  font-size: var(--t-sm);
  color: var(--fg-muted);
  line-height: 1.55;
}

.p-vaults__bars {
  display: grid;
  gap: 6px;
}

.p-vaults__bar-row {
  display: grid;
  grid-template-columns: 70px 1fr 30px;
  align-items: center;
  gap: 10px;
}

.p-vaults__bar-track {
  height: 4px;
  background: var(--line-soft);
  border-radius: 999px;
  overflow: hidden;
}

.p-vaults__bar-fill {
  height: 100%;
  transition: width 600ms var(--ease-out);
}

.p-vaults__bar-count {
  font-size: var(--t-sm);
  color: var(--fg-muted);
  font-family: var(--font-mono);
  text-align: right;
}
</style>

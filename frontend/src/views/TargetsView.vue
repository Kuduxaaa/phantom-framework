<script setup lang="ts">
/**
 * Targets view — secondary nav with search/filter, target detail, and inspector.
 */
import { computed, ref } from 'vue'
import PSecondaryNav from '@/components/organisms/PSecondaryNav.vue'
import PMainPanel from '@/components/organisms/PMainPanel.vue'
import PTargetDetail from '@/components/organisms/PTargetDetail.vue'
import PFindingInspector from '@/components/organisms/PFindingInspector.vue'
import PNavRow from '@/components/molecules/PNavRow.vue'
import PTargetTypeGlyph from '@/components/molecules/PTargetTypeGlyph.vue'
import PSearchInput from '@/components/atoms/PSearchInput.vue'
import PIconButton from '@/components/atoms/PIconButton.vue'
import PIcon from '@/components/atoms/PIcon.vue'
import PEmptyTorii from '@/components/atoms/PEmptyTorii.vue'
import PFilterChip from '@/components/atoms/PFilterChip.vue'
import PNewTargetModal from '@/components/organisms/PNewTargetModal.vue'
import { useTargetsStore } from '@/stores/targets'
import { fmtRel } from '@/utils/time'

type FilterKey = 'all' | 'active' | 'vulnerable' | 'archived'

const targets = useTargetsStore()

const search = ref<string>('')
const filter = ref<FilterKey>('all')
const newTargetOpen = ref<boolean>(false)

const FILTERS: FilterKey[] = ['all', 'active', 'vulnerable', 'archived']

const filtered = computed(() =>
  targets.items.filter((t) => {
    const matchesFilter = filter.value === 'all' || t.status.toLowerCase() === filter.value
    const matchesSearch = !search.value || t.identifier.includes(search.value)
    return matchesFilter && matchesSearch
  }),
)

const totalAssets = computed<number>(() =>
  targets.items.reduce((s, t) => s + t.assets_count, 0),
)
</script>

<template>
  <PSecondaryNav
    title="Targets"
    :footer="`${filtered.length} of ${targets.items.length} · ${totalAssets} assets`"
  >
    <template #action>
      <PIconButton tooltip="Add target" shortcut="N" @click="newTargetOpen = true">
        <PIcon name="plus" :size="14" />
      </PIconButton>
    </template>

    <div class="p-targets__filters">
      <PSearchInput v-model="search" placeholder="Filter targets…" />
      <div class="p-targets__chips">
        <PFilterChip
          v-for="f in FILTERS"
          :key="f"
          :active="filter === f"
          @click="filter = f"
        >{{ f }}</PFilterChip>
      </div>
    </div>

    <PNavRow
      v-for="t in filtered"
      :key="t.id"
      :active="t.id === targets.activeId"
      :label="t.identifier"
      :sub="t.last_scanned_at ? `scanned ${fmtRel(t.last_scanned_at)}` : 'never scanned'"
      @click="targets.setActive(t.id)"
    >
      <template #leading>
        <PTargetTypeGlyph :type="t.target_type" />
      </template>
      <template v-if="t.findings_count > 0" #trailing>
        <span class="tabular">{{ t.findings_count }}</span>
      </template>
    </PNavRow>
  </PSecondaryNav>

  <PMainPanel>
    <PTargetDetail v-if="targets.active" :target="targets.active" />
    <PEmptyTorii
      v-else
      title="Select a target"
      hint="Pick one from the list to see assets, scans, and findings."
    />
  </PMainPanel>

  <PFindingInspector />

  <PNewTargetModal v-model:open="newTargetOpen" />
</template>

<style scoped>
.p-targets__filters {
  padding: 0 4px 8px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.p-targets__chips {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
}
</style>

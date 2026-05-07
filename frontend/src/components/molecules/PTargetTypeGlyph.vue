<script setup lang="ts">
/**
 * Target-type indicator tile — small colored icon for WEB / API / MOBILE / etc.
 */
import { computed } from 'vue'
import PIcon from '../atoms/PIcon.vue'
import type { IconName } from '../icons/icon-paths'
import type { TargetType } from '@/types'

interface Props {
  type: TargetType
}

const props = defineProps<Props>()

interface TypeConfig {
  icon: IconName
  color: string
}

const TYPE_MAP: Partial<Record<TargetType, TypeConfig>> = {
  WEB: { icon: 'globe', color: '#5b8def' },
  API: { icon: 'layers', color: '#e0b03d' },
  MOBILE: { icon: 'target', color: '#b48aff' },
}

const config = computed<TypeConfig>(
  () => TYPE_MAP[props.type] ?? { icon: 'globe', color: 'var(--fg-subtle)' },
)
</script>

<template>
  <span class="p-target-type-glyph" :style="{ color: config.color }">
    <PIcon :name="config.icon" :size="13" />
  </span>
</template>

<style scoped>
.p-target-type-glyph {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 22px;
  height: 22px;
  background: var(--bg-sunken);
  border-radius: var(--r-1);
}
</style>

<script setup lang="ts">
/**
 * Platform identity badge — a small colored icon tile per bug-bounty platform.
 */
import { computed } from 'vue'
import PIcon from '../atoms/PIcon.vue'
import type { IconName } from '../icons/icon-paths'
import type { PlatformType } from '@/types'

interface Props {
  platform: PlatformType
}

const props = defineProps<Props>()

interface PlatformConfig {
  icon: IconName
  color: string
}

const PLATFORM_MAP: Record<PlatformType, PlatformConfig> = {
  HACKERONE: { icon: 'bug', color: '#ec5e5b' },
  BUGCROWD: { icon: 'target', color: '#f26822' },
  INTIGRITI: { icon: 'layers', color: '#5b8def' },
  YESWEHACK: { icon: 'lock', color: '#2bb673' },
  CUSTOM: { icon: 'globe', color: 'var(--fg-subtle)' },
}

const config = computed<PlatformConfig>(() => PLATFORM_MAP[props.platform] ?? PLATFORM_MAP.CUSTOM)
</script>

<template>
  <span class="p-platform-glyph" :style="{ color: config.color }">
    <PIcon :name="config.icon" :size="13" />
  </span>
</template>

<style scoped>
.p-platform-glyph {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 22px;
  height: 22px;
  background: var(--bg-sunken);
  border-radius: var(--r-1);
}
</style>

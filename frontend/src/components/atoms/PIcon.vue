<script setup lang="ts">
/**
 * Single-stroke icon renderer.
 *
 * Looks the icon up in `ICON_PATHS` and emits an SVG that inherits text color
 * via `currentColor`. Defaults to a 16px line-icon at 1.5px stroke weight.
 */
import { computed } from 'vue'
import { ICON_PATHS, type IconName } from '../icons/icon-paths'

interface Props {
  name: IconName
  size?: number
  strokeWidth?: number
}

const props = withDefaults(defineProps<Props>(), {
  size: 16,
  strokeWidth: 1.5,
})

const innerHtml = computed<string>(() => ICON_PATHS[props.name])
</script>

<template>
  <svg
    xmlns="http://www.w3.org/2000/svg"
    :width="size"
    :height="size"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    :stroke-width="strokeWidth"
    stroke-linecap="round"
    stroke-linejoin="round"
    class="p-icon"
    v-html="innerHtml"
  />
</template>

<style scoped>
.p-icon {
  flex-shrink: 0;
  display: inline-block;
  vertical-align: middle;
}
</style>

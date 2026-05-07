<script setup lang="ts">
/**
 * Pulsing dot used to signal in-flight activity (running scans, live capture).
 *
 * When `paused` is true the animation halts and the dot dims to `--fg-faint`.
 */

interface Props {
  paused?: boolean
}

withDefaults(defineProps<Props>(), {
  paused: false,
})
</script>

<template>
  <span class="p-running-pulse" :class="{ 'is-paused': paused }" />
</template>

<style scoped>
.p-running-pulse {
  display: inline-block;
  width: 6px;
  height: 6px;
  border-radius: 999px;
  background: var(--accent);
  animation: phPulse 1.4s var(--ease) infinite;
}

.p-running-pulse.is-paused {
  background: var(--fg-faint);
  animation: none;
}
</style>

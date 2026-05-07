<script setup lang="ts">
/**
 * Geometric, single-stroke Torii mark — used as the application logo.
 *
 * Treated as a logo, not decoration: never used in icon positions or
 * scattered throughout the UI.
 */

interface Props {
  size?: number
  color?: string
}

withDefaults(defineProps<Props>(), {
  size: 18,
})
</script>

<template>
  <svg
    :width="size"
    :height="size"
    viewBox="0 0 24 24"
    fill="none"
    :stroke="color || 'currentColor'"
    stroke-width="1.6"
    stroke-linecap="square"
    aria-hidden="true"
  >
    <path d="M3 6h18" />
    <path d="M5 9h14" />
    <path d="M7 9v11" />
    <path d="M17 9v11" />
    <path d="M6.5 13h11" />
  </svg>
</template>

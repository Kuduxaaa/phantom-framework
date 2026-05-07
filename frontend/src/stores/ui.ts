/**
 * UI store — cross-cutting interface state (command palette, etc.).
 */

import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useUiStore = defineStore('ui', () => {
  const paletteOpen = ref<boolean>(false)

  function openPalette(): void {
    paletteOpen.value = true
  }

  function closePalette(): void {
    paletteOpen.value = false
  }

  function togglePalette(): void {
    paletteOpen.value = !paletteOpen.value
  }

  return { paletteOpen, openPalette, closePalette, togglePalette }
})

/**
 * Drives a streaming-log effect over a static scan transcript.
 *
 * Reveals lines one at a time on a randomized cadence to mimic a live scan,
 * with pause/resume control. Auto-stops when all lines are exposed.
 */

import { computed, onBeforeUnmount, ref, watch } from 'vue'
import type { ScanLine } from '@/types'

const MIN_DELAY_MS = 200
const MAX_JITTER_MS = 280

export function useScanStream(allLines: ScanLine[]) {
  const visibleCount = ref<number>(0)
  const running = ref<boolean>(true)
  let timer: ReturnType<typeof setTimeout> | null = null

  function clearTimer(): void {
    if (timer !== null) {
      clearTimeout(timer)
      timer = null
    }
  }

  function scheduleNext(): void {
    clearTimer()
    if (!running.value) return
    if (visibleCount.value >= allLines.length) return
    const delay = MIN_DELAY_MS + Math.random() * MAX_JITTER_MS
    timer = setTimeout(() => {
      visibleCount.value += 1
    }, delay)
  }

  watch([visibleCount, running], scheduleNext, { immediate: true })

  onBeforeUnmount(clearTimer)

  const visible = computed<ScanLine[]>(() => allLines.slice(0, visibleCount.value))
  const isComplete = computed<boolean>(() => visibleCount.value >= allLines.length)
  const progress = computed<number>(() => (visibleCount.value / allLines.length) * 100)

  function toggle(): void {
    running.value = !running.value
  }

  return { visibleCount, visible, running, isComplete, progress, toggle }
}

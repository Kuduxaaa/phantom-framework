<script setup lang="ts">
/**
 * Backdrop modal dialog.
 *
 * Two-way bound via `v-model:open`. Closes on backdrop click or Escape.
 * Header receives `title`; named slots: default (body), `footer`.
 *
 * Width preset via `size`: `sm` (440px), `md` (560px), `lg` (720px).
 */
import { nextTick, ref, watch } from 'vue'
import PIcon from './PIcon.vue'
import PIconButton from './PIconButton.vue'

interface Props {
  open: boolean
  title: string
  description?: string
  size?: 'sm' | 'md' | 'lg'
  closeOnBackdrop?: boolean
}

const props = withDefaults(defineProps<Props>(), {
  size: 'md',
  closeOnBackdrop: true,
})

const emit = defineEmits<{ 'update:open': [value: boolean] }>()

const panel = ref<HTMLDivElement | null>(null)

watch(
  () => props.open,
  (open) => {
    if (!open) return
    void nextTick(() => {
      const focusable = panel.value?.querySelector<HTMLElement>(
        'input, textarea, select, button, [tabindex]:not([tabindex="-1"])',
      )
      focusable?.focus()
    })
  },
)

function close(): void {
  emit('update:open', false)
}

function onKeydown(event: KeyboardEvent): void {
  if (event.key === 'Escape') close()
}

function onBackdropClick(): void {
  if (props.closeOnBackdrop) close()
}
</script>

<template>
  <Teleport to="body">
    <Transition name="p-modal">
      <div
        v-if="open"
        class="p-modal"
        role="dialog"
        aria-modal="true"
        :aria-label="title"
        @click.self="onBackdropClick"
        @keydown="onKeydown"
      >
        <div
          ref="panel"
          class="p-modal__panel"
          :class="`p-modal__panel--${size}`"
          @click.stop
        >
          <header class="p-modal__head">
            <div class="p-modal__head-text">
              <h2 class="p-modal__title">{{ title }}</h2>
              <p v-if="description" class="p-modal__description">{{ description }}</p>
            </div>
            <PIconButton tooltip="Close" shortcut="esc" tooltip-position="left" @click="close">
              <PIcon name="close" :size="14" />
            </PIconButton>
          </header>

          <div class="p-modal__body">
            <slot />
          </div>

          <footer v-if="$slots.footer" class="p-modal__footer">
            <slot name="footer" :close="close" />
          </footer>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.p-modal {
  position: fixed;
  inset: 0;
  z-index: 90;
  background: rgba(0, 0, 0, 0.42);
  display: flex;
  align-items: flex-start;
  justify-content: center;
  padding-top: min(12vh, 100px);
  backdrop-filter: blur(2px);
}

.p-modal__panel {
  display: flex;
  flex-direction: column;
  background: var(--bg-elev);
  border: 1px solid var(--line-strong);
  border-radius: var(--r-3);
  box-shadow: var(--shadow-3);
  max-height: 80vh;
  animation: phPaletteIn var(--dur) var(--ease-out);
}

.p-modal__panel--sm {
  width: 440px;
}

.p-modal__panel--md {
  width: 560px;
}

.p-modal__panel--lg {
  width: 720px;
}

.p-modal__head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  padding: 18px 20px;
  border-bottom: 1px solid var(--line);
}

.p-modal__head-text {
  flex: 1;
  min-width: 0;
}

.p-modal__title {
  margin: 0;
  font-family: var(--font-display);
  font-size: 17px;
  font-weight: 600;
  letter-spacing: -0.018em;
  color: var(--fg);
  line-height: 1.25;
}

.p-modal__description {
  margin: 4px 0 0;
  font-size: var(--t-sm);
  color: var(--fg-subtle);
  line-height: 1.5;
}

.p-modal__body {
  padding: 18px 20px;
  overflow-y: auto;
  display: grid;
  gap: 14px;
}

.p-modal__footer {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  padding: 12px 20px;
  border-top: 1px solid var(--line);
  background: var(--bg);
}

.p-modal-enter-active,
.p-modal-leave-active {
  transition: opacity var(--dur) var(--ease-out);
}

.p-modal-enter-from,
.p-modal-leave-to {
  opacity: 0;
}
</style>

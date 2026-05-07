<script setup lang="ts">
/**
 * Numbered step card used by the visual signature builder.
 *
 * Stack vertically; each card shows a step number, title, optional caption,
 * action slot, and an arrow connector to the next card.
 */

interface Props {
  step: number
  title: string
  caption?: string
  /** Show the down-arrow connector below the card. Default true. */
  connector?: boolean
}

withDefaults(defineProps<Props>(), {
  connector: true,
})
</script>

<template>
  <section class="p-builder-step">
    <article class="p-builder-step__card">
      <header class="p-builder-step__head">
        <span class="p-builder-step__num">{{ step }}</span>
        <div class="p-builder-step__titles">
          <h3 class="p-builder-step__title">{{ title }}</h3>
          <p v-if="caption" class="p-builder-step__caption">{{ caption }}</p>
        </div>
        <div v-if="$slots.action" class="p-builder-step__action">
          <slot name="action" />
        </div>
      </header>
      <div class="p-builder-step__body">
        <slot />
      </div>
    </article>
    <div v-if="connector" class="p-builder-step__connector" aria-hidden="true">
      <svg width="14" height="22" viewBox="0 0 14 22" fill="none">
        <path
          d="M7 0 V18 M2 13 L7 18 L12 13"
          stroke="var(--line-strong)"
          stroke-width="1.2"
          stroke-linecap="round"
          stroke-linejoin="round"
        />
      </svg>
    </div>
  </section>
</template>

<style scoped>
.p-builder-step {
  display: flex;
  flex-direction: column;
  align-items: stretch;
}

.p-builder-step__card {
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: var(--r-3);
  overflow: hidden;
  box-shadow: var(--shadow-1);
}

.p-builder-step__head {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 14px 16px;
  border-bottom: 1px solid var(--line);
  background: var(--bg-elev);
}

.p-builder-step__num {
  width: 24px;
  height: 24px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-family: var(--font-mono);
  font-size: 12px;
  font-weight: 600;
  color: var(--accent);
  background: var(--accent-soft);
  border-radius: var(--r-full);
  flex-shrink: 0;
}

.p-builder-step__titles {
  flex: 1;
  min-width: 0;
}

.p-builder-step__title {
  margin: 0;
  font-family: var(--font-display);
  font-size: 14px;
  font-weight: 600;
  color: var(--fg);
  letter-spacing: -0.012em;
}

.p-builder-step__caption {
  margin: 2px 0 0;
  font-size: var(--t-xs);
  color: var(--fg-subtle);
  line-height: 1.45;
}

.p-builder-step__body {
  padding: 16px;
  display: grid;
  gap: 16px;
}

.p-builder-step__connector {
  display: flex;
  justify-content: center;
  padding: 4px 0;
  color: var(--line-strong);
}
</style>

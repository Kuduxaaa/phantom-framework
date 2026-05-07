<script setup lang="ts">
/**
 * Proxy "Intercept" sub-pane — held requests list + edit-and-forward editor.
 */
import { computed, ref } from 'vue'
import PIcon from '../atoms/PIcon.vue'
import PButton from '../atoms/PButton.vue'
import PEmptyTorii from '../atoms/PEmptyTorii.vue'
import { useProxyStore } from '@/stores/proxy'
import { methodColor } from '@/utils/format'

const proxy = useProxyStore()

const heldId = ref<number | null>(proxy.intercepted[0]?.id ?? null)

const held = computed(() => proxy.intercepted.find((t) => t.id === heldId.value) ?? proxy.intercepted[0])

const draft = computed<string>(() => {
  if (!held.value) return ''
  return `${held.value.method} ${held.value.path} HTTP/1.1
Host: ${held.value.host}
User-Agent: Mozilla/5.0 phantom-proxy
Accept: ${held.value.mime}
Authorization: Bearer eyJhbGc…
Cookie: session=a8f3…; csrf=4d11

${held.value.method === 'POST' ? '{\n  "username": "admin",\n  "password": "P@ssw0rd!"\n}' : ''}`
})
</script>

<template>
  <div v-if="!proxy.intercepted.length" class="p-proxy-intercept__empty">
    <PEmptyTorii
      title="Nothing held"
      hint="Toggle Intercept to start holding requests for inspection before they're forwarded."
    />
  </div>
  <div v-else class="p-proxy-intercept">
    <aside class="p-proxy-intercept__list">
      <div class="p-proxy-intercept__list-head">
        <span class="label">Held · {{ proxy.intercepted.length }}</span>
        <span class="p-proxy-intercept__live">
          <span class="p-proxy-intercept__live-dot" />intercepting
        </span>
      </div>
      <button
        v-for="(t, i) in proxy.intercepted"
        :key="t.id"
        type="button"
        class="p-proxy-intercept__row"
        :class="{ 'is-active': held?.id === t.id }"
        @click="heldId = t.id"
      >
        <div class="p-proxy-intercept__row-meta">
          <span
            class="p-proxy-intercept__row-method"
            :style="{ color: methodColor(t.method) }"
          >{{ t.method }}</span>
          <span class="p-proxy-intercept__row-num">#{{ i + 1 }}</span>
        </div>
        <div class="p-proxy-intercept__row-path">{{ t.host }}{{ t.path }}</div>
      </button>
    </aside>

    <section class="p-proxy-intercept__editor">
      <div class="p-proxy-intercept__bar">
        <PButton variant="accent" size="sm">
          <template #icon><PIcon name="arrow-right" :size="12" /></template>
          Forward
        </PButton>
        <PButton variant="secondary" size="sm">
          <template #icon><PIcon name="close" :size="12" /></template>
          Drop
        </PButton>
        <PButton variant="ghost" size="sm">
          <template #icon><PIcon name="pause" :size="12" /></template>
          Forward all
        </PButton>
        <span class="p-proxy-intercept__bar-spacer" />
        <span class="p-proxy-intercept__bar-hint">edit then forward</span>
      </div>
      <textarea readonly class="p-proxy-intercept__textarea" :value="draft" />
    </section>
  </div>
</template>

<style scoped>
.p-proxy-intercept {
  flex: 1;
  display: flex;
  min-height: 0;
}

.p-proxy-intercept__empty {
  padding: 40px;
  flex: 1;
}

.p-proxy-intercept__list {
  width: 260px;
  flex-shrink: 0;
  border-right: 1px solid var(--line);
  background: var(--bg-elev);
  overflow: auto;
}

.p-proxy-intercept__list-head {
  padding: 10px 12px;
  border-bottom: 1px solid var(--line);
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.p-proxy-intercept__live {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 11px;
  color: var(--accent);
}

.p-proxy-intercept__live-dot {
  width: 6px;
  height: 6px;
  border-radius: 999px;
  background: var(--accent);
}

.p-proxy-intercept__row {
  width: 100%;
  padding: 8px 12px;
  text-align: left;
  background: transparent;
  border-bottom: 1px solid var(--line-soft);
}

.p-proxy-intercept__row.is-active {
  background: var(--selected);
}

.p-proxy-intercept__row:hover:not(.is-active) {
  background: var(--hover);
}

.p-proxy-intercept__row-meta {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-bottom: 2px;
}

.p-proxy-intercept__row-method {
  font-family: var(--font-mono);
  font-size: 10.5px;
  font-weight: 600;
}

.p-proxy-intercept__row-num {
  font-family: var(--font-mono);
  font-size: 10.5px;
  color: var(--fg-faint);
}

.p-proxy-intercept__row-path {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--fg);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.p-proxy-intercept__editor {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.p-proxy-intercept__bar {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 10px 16px;
  border-bottom: 1px solid var(--line);
}

.p-proxy-intercept__bar-spacer {
  flex: 1;
}

.p-proxy-intercept__bar-hint {
  font-size: 11px;
  color: var(--fg-faint);
  font-family: var(--font-mono);
}

.p-proxy-intercept__textarea {
  flex: 1;
  padding: 16px;
  border: 0;
  outline: none;
  resize: none;
  background: var(--bg-sunken);
  color: var(--fg);
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.7;
}
</style>

<script setup lang="ts">
/**
 * Side-by-side evidence pane used in the finding inspector.
 *
 * Two tones — `request` and `response` — drive the leading dot color.
 * Optional `highlight` array marks substrings inside the body with a critical-tone
 * mark so reviewers can spot them at a glance.
 */
import { computed } from 'vue'
import PIcon from '../atoms/PIcon.vue'

interface Props {
  title: string
  tone: 'request' | 'response'
  body: string
  highlight?: string[]
}

const props = withDefaults(defineProps<Props>(), {
  highlight: () => [],
})

const toneColor = computed<string>(() =>
  props.tone === 'request' ? 'var(--sev-info)' : 'var(--sev-medium)',
)

interface Segment {
  text: string
  highlighted: boolean
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

const segments = computed<Segment[]>(() => {
  if (!props.highlight.length) return [{ text: props.body, highlighted: false }]
  const pattern = new RegExp(`(${props.highlight.map(escapeRegex).join('|')})`, 'g')
  const parts: Segment[] = []
  let last = 0
  let match: RegExpExecArray | null
  while ((match = pattern.exec(props.body))) {
    if (match.index > last) parts.push({ text: props.body.slice(last, match.index), highlighted: false })
    parts.push({ text: match[1] ?? '', highlighted: true })
    last = match.index + match[0].length
  }
  if (last < props.body.length) parts.push({ text: props.body.slice(last), highlighted: false })
  return parts
})
</script>

<template>
  <div class="p-evidence-pane">
    <div class="p-evidence-pane__header">
      <span class="p-evidence-pane__dot" :style="{ background: toneColor }" />
      <span class="label">{{ title }}</span>
      <span class="p-evidence-pane__spacer" />
      <button type="button" class="p-evidence-pane__copy" title="Copy">
        <PIcon name="copy" :size="11" />
      </button>
    </div>
    <pre class="p-evidence-pane__body"><template v-for="(seg, i) in segments" :key="i"><mark v-if="seg.highlighted" class="p-evidence-pane__mark">{{ seg.text }}</mark><template v-else>{{ seg.text }}</template></template></pre>
  </div>
</template>

<style scoped>
.p-evidence-pane {
  border: 1px solid var(--line);
  border-radius: var(--r-2);
  overflow: hidden;
  background: var(--surface);
}

.p-evidence-pane__header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 10px;
  border-bottom: 1px solid var(--line);
  background: var(--bg-elev);
}

.p-evidence-pane__dot {
  width: 6px;
  height: 6px;
  border-radius: 999px;
}

.p-evidence-pane__spacer {
  flex: 1;
}

.p-evidence-pane__copy {
  color: var(--fg-subtle);
}

.p-evidence-pane__copy:hover {
  color: var(--fg);
}

.p-evidence-pane__body {
  margin: 0;
  padding: 10px 12px;
  font-family: var(--font-mono);
  font-size: 11px;
  line-height: 1.7;
  color: var(--fg);
  overflow: auto;
  white-space: pre-wrap;
}

.p-evidence-pane__mark {
  background: var(--sev-critical-bg);
  color: var(--sev-critical);
  padding: 0 2px;
  border-radius: 2px;
}
</style>

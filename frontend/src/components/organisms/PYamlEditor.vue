<script setup lang="ts">
/**
 * Read-only YAML viewer with simple syntax highlighting.
 *
 * Uses the YAML tokenizer in `@/utils/yaml`. Each token kind maps to a
 * theme color via `TOKEN_COLORS`.
 */
import { computed } from 'vue'
import { tokenizeYamlLine, type TokenKind } from '@/utils/yaml'

interface Props {
  source: string
}

const props = defineProps<Props>()

const TOKEN_COLORS: Record<TokenKind, string> = {
  plain: 'var(--fg)',
  indent: 'var(--fg)',
  dash: 'var(--fg-subtle)',
  key: 'var(--sev-info)',
  colon: 'var(--fg-subtle)',
  string: 'var(--ok)',
  template: 'var(--accent)',
  literal: 'var(--sev-medium)',
  number: 'var(--sev-medium)',
  comment: 'var(--fg-faint)',
}

const lines = computed(() =>
  props.source.split('\n').map((line, idx) => ({
    index: idx + 1,
    tokens: tokenizeYamlLine(line),
  })),
)
</script>

<template>
  <div class="p-yaml-editor">
    <pre class="p-yaml-editor__pre">
      <template v-for="line in lines" :key="line.index">
        <span class="p-yaml-editor__gutter">{{ line.index }}</span><code class="p-yaml-editor__code"><span
          v-for="(tok, ti) in line.tokens"
          :key="ti"
          :style="{ color: TOKEN_COLORS[tok.kind], fontStyle: tok.kind === 'comment' ? 'italic' : undefined }"
        >{{ tok.text }}</span></code>
      </template>
    </pre>
  </div>
</template>

<style scoped>
.p-yaml-editor {
  flex: 1;
  overflow: auto;
  background: var(--bg);
}

.p-yaml-editor__pre {
  margin: 0;
  padding: 0;
  display: grid;
  grid-template-columns: 50px 1fr;
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.7;
}

.p-yaml-editor__gutter {
  padding: 0 12px 0 0;
  text-align: right;
  color: var(--fg-faint);
  user-select: none;
  border-right: 1px solid var(--line);
  font-variant-numeric: tabular-nums;
}

.p-yaml-editor__code {
  padding: 0 16px;
}
</style>

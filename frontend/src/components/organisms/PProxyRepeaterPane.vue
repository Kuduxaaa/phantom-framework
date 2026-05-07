<script setup lang="ts">
/**
 * Proxy "Repeater" sub-pane — multi-tab edit-and-resend with side-by-side request/response.
 */
import { computed } from 'vue'
import PIcon from '../atoms/PIcon.vue'
import PButton from '../atoms/PButton.vue'
import { formatBytes, statusColor } from '@/utils/format'
import { useProxyStore } from '@/stores/proxy'

const proxy = useProxyStore()
const req = computed(() => proxy.selected ?? proxy.items[0]!)

const tabs = computed(() => [
  { id: 'r1', label: `#1 · ${req.value.method} ${req.value.path.slice(0, 24)}`, active: true },
  { id: 'r2', label: '#2 · POST /v2/login', active: false },
  { id: 'r3', label: '#3 · GET /admin', active: false },
])

const requestDraft = computed<string>(
  () => `${req.value.method} ${req.value.path} HTTP/1.1
Host: ${req.value.host}
Authorization: Bearer eyJhbGc…
Content-Type: application/json
User-Agent: phantom-repeater/1.0

${req.value.method === 'POST' || req.value.method === 'PUT' ? '{\n  "id": 1\n}' : ''}`,
)

const responseDraft = computed<string>(
  () => `HTTP/1.1 ${req.value.status} ${req.value.status === 200 ? 'OK' : ''}
Content-Type: ${req.value.mime}
Content-Length: ${req.value.size}
Server: nginx/1.24.0

${req.value.mime.includes('json') ? '{\n  "data": [\n    { "id": 1, "name": "alice" },\n    { "id": 2, "name": "bob" }\n  ],\n  "meta": { "total": 47 }\n}' : '<!DOCTYPE html>...'}`,
)
</script>

<template>
  <div class="p-proxy-repeater">
    <div class="p-proxy-repeater__tabs">
      <button
        v-for="t in tabs"
        :key="t.id"
        type="button"
        class="p-proxy-repeater__tab"
        :class="{ 'is-active': t.active }"
      >{{ t.label }}</button>
      <button type="button" class="p-proxy-repeater__add">
        <PIcon name="plus" :size="12" />
      </button>
      <span class="p-proxy-repeater__spacer" />
      <PButton variant="accent" size="sm" class="p-proxy-repeater__send">
        <template #icon><PIcon name="play" :size="12" /></template>
        Send
      </PButton>
    </div>

    <div class="p-proxy-repeater__split">
      <div class="p-proxy-repeater__col">
        <div class="p-proxy-repeater__col-head">
          <span class="label">Request</span>
          <span class="p-proxy-repeater__hint">edit & resend</span>
        </div>
        <textarea class="p-proxy-repeater__editor" :value="requestDraft" />
      </div>
      <div class="p-proxy-repeater__col p-proxy-repeater__col--right">
        <div class="p-proxy-repeater__col-head">
          <span class="label">Response</span>
          <span class="p-proxy-repeater__meta">
            <span :style="{ color: statusColor(req.status) }">{{ req.status }}</span>
            <span>·</span>
            <span>{{ req.dur }}ms</span>
            <span>·</span>
            <span>{{ formatBytes(req.size) }}</span>
          </span>
        </div>
        <pre class="p-proxy-repeater__pre">{{ responseDraft }}</pre>
      </div>
    </div>
  </div>
</template>

<style scoped>
.p-proxy-repeater {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-height: 0;
}

.p-proxy-repeater__tabs {
  display: flex;
  align-items: center;
  border-bottom: 1px solid var(--line);
  background: var(--bg-elev);
}

.p-proxy-repeater__tab {
  padding: 8px 14px;
  font-size: 11px;
  font-family: var(--font-mono);
  color: var(--fg-subtle);
  border-right: 1px solid var(--line);
  background: transparent;
  border-bottom: 1.5px solid transparent;
}

.p-proxy-repeater__tab.is-active {
  color: var(--fg);
  background: var(--bg);
  border-bottom-color: var(--accent);
}

.p-proxy-repeater__add {
  padding: 8px 12px;
  color: var(--fg-subtle);
}

.p-proxy-repeater__spacer {
  flex: 1;
}

.p-proxy-repeater__send {
  margin-right: 12px;
}

.p-proxy-repeater__split {
  flex: 1;
  display: grid;
  grid-template-columns: 1fr 1fr;
  min-height: 0;
}

.p-proxy-repeater__col {
  display: flex;
  flex-direction: column;
  border-right: 1px solid var(--line);
  min-height: 0;
}

.p-proxy-repeater__col--right {
  border-right: 0;
}

.p-proxy-repeater__col-head {
  padding: 6px 12px;
  border-bottom: 1px solid var(--line);
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.p-proxy-repeater__hint {
  font-size: 10.5px;
  color: var(--fg-faint);
  font-family: var(--font-mono);
}

.p-proxy-repeater__meta {
  display: inline-flex;
  gap: 8px;
  font-size: 10.5px;
  color: var(--fg-subtle);
  font-family: var(--font-mono);
}

.p-proxy-repeater__editor,
.p-proxy-repeater__pre {
  flex: 1;
  margin: 0;
  padding: 14px;
  border: 0;
  outline: none;
  resize: none;
  background: var(--bg-sunken);
  color: var(--fg);
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.7;
  overflow: auto;
}
</style>

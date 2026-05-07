<script setup lang="ts">
/**
 * "New signature" modal — seeds a template entry and selects it.
 */
import { computed, ref } from 'vue'
import PModal from '../atoms/PModal.vue'
import PFormField from '../atoms/PFormField.vue'
import PInput from '../atoms/PInput.vue'
import PSelect from '../atoms/PSelect.vue'
import PTextarea from '../atoms/PTextarea.vue'
import PButton from '../atoms/PButton.vue'
import { useTemplatesStore } from '@/stores/templates'
import type { SignatureTemplate, Severity } from '@/types'

interface Props {
  open: boolean
}

defineProps<Props>()

const emit = defineEmits<{ 'update:open': [value: boolean] }>()

const templates = useTemplatesStore()

const name = ref<string>('')
const severity = ref<Lowercase<Severity>>('medium')
const category = ref<string>('injection')
const description = ref<string>('')

const SEVERITY_OPTIONS = [
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'info', label: 'Info' },
]

const CATEGORY_OPTIONS = [
  { value: 'injection', label: 'Injection' },
  { value: 'exposure', label: 'Exposure' },
  { value: 'authentication', label: 'Authentication' },
  { value: 'misconfiguration', label: 'Misconfiguration' },
  { value: 'redirect', label: 'Redirect' },
  { value: 'ssrf', label: 'SSRF' },
]

const canSubmit = computed<boolean>(() => name.value.trim() !== '')

function slug(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
}

function close(): void {
  emit('update:open', false)
}

function reset(): void {
  name.value = ''
  severity.value = 'medium'
  category.value = 'injection'
  description.value = ''
}

function submit(): void {
  if (!canSubmit.value) return
  const id = `t${String(templates.items.length + 1).padStart(2, '0')}`
  const tpl: SignatureTemplate = {
    id,
    signature_id: slug(name.value.trim()),
    name: name.value.trim(),
    severity: severity.value,
    category: category.value,
    tags: [],
    is_active: true,
    execution_count: 0,
    success_count: 0,
    version: '1.0',
    author: 'kuduxaaa',
  }
  templates.items.push(tpl)
  templates.setActive(tpl.id)
  reset()
  close()
}
</script>

<template>
  <PModal
    :open="open"
    title="New signature"
    description="Define a vulnerability detection template. You can refine matchers and payloads in the builder afterwards."
    size="md"
    @update:open="(v: boolean) => emit('update:open', v)"
  >
    <PFormField label="Name" required>
      <PInput v-model="name" placeholder="GraphQL Introspection Enabled" autofocus />
    </PFormField>

    <PFormField label="Severity">
      <PSelect v-model="severity" :options="SEVERITY_OPTIONS" />
    </PFormField>

    <PFormField label="Category">
      <PSelect v-model="category" :options="CATEGORY_OPTIONS" />
    </PFormField>

    <PFormField label="Description">
      <PTextarea v-model="description" placeholder="What this signature detects, briefly." :rows="3" />
    </PFormField>

    <template #footer>
      <PButton variant="ghost" @click="close">Cancel</PButton>
      <PButton variant="accent" :disabled="!canSubmit" @click="submit">Create signature</PButton>
    </template>
  </PModal>
</template>

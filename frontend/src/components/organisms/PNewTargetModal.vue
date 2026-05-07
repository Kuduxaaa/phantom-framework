<script setup lang="ts">
/**
 * "New target" modal — adds an asset to the targets store.
 */
import { computed, ref } from 'vue'
import PModal from '../atoms/PModal.vue'
import PFormField from '../atoms/PFormField.vue'
import PInput from '../atoms/PInput.vue'
import PSelect from '../atoms/PSelect.vue'
import PButton from '../atoms/PButton.vue'
import { useTargetsStore } from '@/stores/targets'
import type { Target, TargetType } from '@/types'

interface Props {
  open: boolean
}

defineProps<Props>()

const emit = defineEmits<{ 'update:open': [value: boolean] }>()

const targets = useTargetsStore()

const identifier = ref<string>('')
const targetType = ref<TargetType>('WEB')
const description = ref<string>('')

const TYPE_OPTIONS = [
  { value: 'WEB', label: 'Web application' },
  { value: 'API', label: 'API endpoint' },
  { value: 'MOBILE', label: 'Mobile app' },
  { value: 'NETWORK', label: 'Network host' },
  { value: 'CLOUD', label: 'Cloud resource' },
  { value: 'OTHER', label: 'Other' },
]

const canSubmit = computed<boolean>(() => identifier.value.trim() !== '')

function close(): void {
  emit('update:open', false)
}

function reset(): void {
  identifier.value = ''
  targetType.value = 'WEB'
  description.value = ''
}

function submit(): void {
  if (!canSubmit.value) return
  const id = Math.max(0, ...targets.items.map((t) => t.id)) + 1
  const target: Target = {
    id,
    identifier: identifier.value.trim(),
    target_type: targetType.value,
    status: 'ACTIVE',
    is_wildcard: identifier.value.includes('*'),
    ip_address: null,
    tech_stack: [],
    risk_score: 0,
    last_scanned_at: null,
    assets_count: 0,
    findings_count: 0,
  }
  targets.items.push(target)
  targets.setActive(target.id)
  reset()
  close()
}
</script>

<template>
  <PModal
    :open="open"
    title="New target"
    description="Add a host, endpoint, or asset to scan within this vault."
    @update:open="(v: boolean) => emit('update:open', v)"
  >
    <PFormField label="Identifier" required hint="Domain, URL, or wildcard. e.g., api.acme.io or *.acme.com">
      <PInput v-model="identifier" placeholder="api.acme.io" mono autofocus />
    </PFormField>

    <PFormField label="Type">
      <PSelect v-model="targetType" :options="TYPE_OPTIONS" />
    </PFormField>

    <PFormField label="Description" hint="Optional. Notes about scope or testing constraints.">
      <PInput v-model="description" placeholder="Public REST API used by the mobile app" />
    </PFormField>

    <template #footer>
      <PButton variant="ghost" @click="close">Cancel</PButton>
      <PButton variant="accent" :disabled="!canSubmit" @click="submit">Add target</PButton>
    </template>
  </PModal>
</template>

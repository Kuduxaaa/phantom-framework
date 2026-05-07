<script setup lang="ts">
/**
 * "New vault" modal — creates a Vault entry from name, platform, and target domain.
 *
 * Submits via the vaults store. Two-way bound via `v-model:open`.
 */
import { computed, ref, watch } from 'vue'
import PModal from '../atoms/PModal.vue'
import PFormField from '../atoms/PFormField.vue'
import PInput from '../atoms/PInput.vue'
import PSelect from '../atoms/PSelect.vue'
import PButton from '../atoms/PButton.vue'
import { useVaultsStore } from '@/stores/vaults'
import type { PlatformType, Vault } from '@/types'

interface Props {
  open: boolean
}

defineProps<Props>()

const emit = defineEmits<{ 'update:open': [value: boolean] }>()

const vaults = useVaultsStore()

const name = ref<string>('')
const platform = ref<PlatformType>('HACKERONE')
const targetDomain = ref<string>('')
const programUrl = ref<string>('')

const PLATFORM_OPTIONS = [
  { value: 'HACKERONE', label: 'HackerOne' },
  { value: 'BUGCROWD', label: 'Bugcrowd' },
  { value: 'INTIGRITI', label: 'Intigriti' },
  { value: 'YESWEHACK', label: 'YesWeHack' },
  { value: 'CUSTOM', label: 'Custom' },
]

watch(
  () => name.value,
  () => {
    /* placeholder for derived values; kept for clarity */
  },
)

const canSubmit = computed<boolean>(() => name.value.trim() !== '' && targetDomain.value.trim() !== '')

function close(): void {
  emit('update:open', false)
}

function reset(): void {
  name.value = ''
  platform.value = 'HACKERONE'
  targetDomain.value = ''
  programUrl.value = ''
}

function submit(): void {
  if (!canSubmit.value) return
  const nextId = Math.max(0, ...vaults.items.map((v) => v.id)) + 1
  const vault: Vault = {
    id: nextId,
    name: name.value.trim(),
    platform: platform.value,
    target_domain: targetDomain.value.trim(),
    program_url: programUrl.value.trim() || undefined,
    scope_rules: { in: [`*.${targetDomain.value.trim()}`], out: [] },
    stats: { targets: 0, findings: 0, critical: 0, high: 0, scans_running: 0 },
    last_activity: new Date(),
  }
  vaults.items.push(vault)
  vaults.setActive(vault.id)
  reset()
  close()
}
</script>

<template>
  <PModal
    :open="open"
    title="New vault"
    description="Track a bug bounty program — its scope, targets, and findings live inside the vault."
    size="md"
    @update:open="(v: boolean) => emit('update:open', v)"
  >
    <PFormField label="Program name" required>
      <PInput v-model="name" placeholder="Acme Corp" autofocus />
    </PFormField>

    <PFormField label="Platform">
      <PSelect v-model="platform" :options="PLATFORM_OPTIONS" />
    </PFormField>

    <PFormField label="Target domain" required hint="The primary domain. Wildcard scope will be derived from it.">
      <PInput v-model="targetDomain" placeholder="acme.com" mono />
    </PFormField>

    <PFormField label="Program URL">
      <PInput v-model="programUrl" placeholder="https://hackerone.com/acme" mono type="url" />
    </PFormField>

    <template #footer>
      <PButton variant="ghost" @click="close">Cancel</PButton>
      <PButton variant="accent" :disabled="!canSubmit" @click="submit">Create vault</PButton>
    </template>
  </PModal>
</template>

<script setup lang="ts">
/**
 * "New note" modal — title + body + type. Submits via the notes store.
 */
import { computed, ref } from 'vue'
import PModal from '../atoms/PModal.vue'
import PFormField from '../atoms/PFormField.vue'
import PInput from '../atoms/PInput.vue'
import PSelect from '../atoms/PSelect.vue'
import PTextarea from '../atoms/PTextarea.vue'
import PButton from '../atoms/PButton.vue'
import { useNotesStore, type NoteType } from '@/stores/notes'

interface Props {
  open: boolean
}

defineProps<Props>()

const emit = defineEmits<{ 'update:open': [value: boolean] }>()

const notes = useNotesStore()

const title = ref<string>('')
const content = ref<string>('')
const noteType = ref<NoteType>('GENERAL')

const TYPE_OPTIONS = [
  { value: 'GENERAL', label: 'General' },
  { value: 'FINDING', label: 'Finding' },
  { value: 'TODO', label: 'Todo' },
  { value: 'METHODOLOGY', label: 'Methodology' },
  { value: 'PERSONAL', label: 'Personal' },
]

const canSubmit = computed<boolean>(() => content.value.trim() !== '')

function close(): void {
  emit('update:open', false)
}

function reset(): void {
  title.value = ''
  content.value = ''
  noteType.value = 'GENERAL'
}

function submit(): void {
  if (!canSubmit.value) return
  notes.add({ title: title.value.trim(), content: content.value.trim(), note_type: noteType.value })
  reset()
  close()
}
</script>

<template>
  <PModal
    :open="open"
    title="New note"
    description="A free-form note scoped to the current engagement."
    @update:open="(v: boolean) => emit('update:open', v)"
  >
    <PFormField label="Title">
      <PInput v-model="title" placeholder="JWT auth flow — open questions" autofocus />
    </PFormField>

    <PFormField label="Type">
      <PSelect v-model="noteType" :options="TYPE_OPTIONS" />
    </PFormField>

    <PFormField label="Note" required>
      <PTextarea v-model="content" placeholder="Markdown is supported." :rows="8" />
    </PFormField>

    <template #footer>
      <PButton variant="ghost" @click="close">Cancel</PButton>
      <PButton variant="accent" :disabled="!canSubmit" @click="submit">Save note</PButton>
    </template>
  </PModal>
</template>

<script setup lang="ts">
/**
 * Generic placeholder used for routes that don't have a real screen yet
 * (e.g., Workflows, Notes).
 *
 * For Notes, the action button opens the new-note modal. For other routes
 * the action button is informational.
 */
import { ref } from 'vue'
import PMainPanel from '@/components/organisms/PMainPanel.vue'
import PEmptyTorii from '@/components/atoms/PEmptyTorii.vue'
import PButton from '@/components/atoms/PButton.vue'
import PIcon from '@/components/atoms/PIcon.vue'
import PNewNoteModal from '@/components/organisms/PNewNoteModal.vue'

interface Props {
  title: string
  hint: string
  actionLabel?: string
  actionKind?: 'note' | 'workflow' | 'none'
}

const props = withDefaults(defineProps<Props>(), {
  actionKind: 'none',
})

const newNoteOpen = ref<boolean>(false)

function onAction(): void {
  if (props.actionKind === 'note') newNoteOpen.value = true
}
</script>

<template>
  <PMainPanel>
    <PEmptyTorii :title="title" :hint="hint">
      <template v-if="actionLabel" #action>
        <PButton variant="primary" @click="onAction">
          <template #icon><PIcon name="plus" :size="12" /></template>
          {{ actionLabel }}
        </PButton>
      </template>
    </PEmptyTorii>
  </PMainPanel>

  <PNewNoteModal v-if="actionKind === 'note'" v-model:open="newNoteOpen" />
</template>

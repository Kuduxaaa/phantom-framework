/**
 * Notes store — free-form markdown notes scoped to vault or target.
 */

import { defineStore } from 'pinia'
import { ref } from 'vue'

export type NoteType = 'GENERAL' | 'FINDING' | 'TODO' | 'METHODOLOGY' | 'PERSONAL'

export interface Note {
  id: number
  title: string
  content: string
  note_type: NoteType
  is_pinned: boolean
  created_at: Date
}

export const useNotesStore = defineStore('notes', () => {
  const items = ref<Note[]>([])

  function add(input: Pick<Note, 'title' | 'content' | 'note_type'>): Note {
    const id = Math.max(0, ...items.value.map((n) => n.id)) + 1
    const note: Note = {
      id,
      title: input.title,
      content: input.content,
      note_type: input.note_type,
      is_pinned: false,
      created_at: new Date(),
    }
    items.value.unshift(note)
    return note
  }

  return { items, add }
})

import enum

from typing import Optional

from sqlalchemy import (
    Column,
    String,
    Text,
    Integer,
    ForeignKey,
    JSON,
    Boolean,
    Enum as SaEnum
)

from sqlalchemy.orm import relationship
from app.models.base import BaseModel

class NoteType(str, enum.Enum):
    """
    Enum representing type of note.
    """

    GENERAL     = 'general'
    FINDING     = 'finding'
    TODO        = 'todo'
    METHODOLOGY = 'methodology'
    PERSONAL    = 'personal'

class Note(BaseModel):
    """
    Represents a Note model.
    """

    __tablename__ = 'notes'

    title = Column(String(255), nullable=True)
    content = Column(Text, nullable=False)

    note_type = Column(SaEnum(NoteType), default=NoteType.GENERAL, nullable=False)
    note_tags = Column(JSON, default=lambda: [])
    is_pinned = Column(Boolean, default=False)

    vault_id = Column(Integer, ForeignKey('vaults.id', ondelete='CASCADE'), nullable=True)
    vault = relationship('Vault', backref='notes')

    target_id = Column(Integer, ForeignKey('targets.id', ondelete='CASCADE'), nullable=True)
    target = relationship('Target', backref='notes')

    def __repr__(self) -> str:
        """
        Text representation of Note model
        """

        return f'<Note {self.id}>'

    @property
    def context(self) -> str:
        """
        Helper to see where this note belongs.
        """

        if self.target:
            return f'Target: {self.target.identifier}'

        if self.vault:
            return f'Vault: {self.vault.name}'
        
        return 'Global'


    def add_tag(self, tag: str) -> None:
        """
        Add a tag to the note.
        """

        if tag not in self.note_tags:
            self.note_tags.append(tag)

    def remove_tag(self, tag: str) -> None:
        """
        Remove a tag from the note.
        """

        if tag in self.note_tags:
            self.note_tags.remove(tag)
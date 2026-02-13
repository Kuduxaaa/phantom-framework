import enum

from typing import Optional, Dict, Any
from datetime import datetime

from sqlalchemy import (
    Column,
    String,
    Integer,
    ForeignKey,
    DateTime,
    JSON,
    Enum as SaEnum,
    Boolean,
    Text
)

from sqlalchemy.orm import relationship, backref
from app.models.base import BaseModel

class TargetType(str, enum.Enum):
    """
    Enum representing different types of targets.
    """

    WEB     = 'web'
    API     = 'api'
    MOBILE  = 'mobile'
    NETWORK = 'network'
    CLOUD   = 'cloud'
    OTHER   = 'other'

class TargetStatus(str, enum.Enum):
    """
    Enum representing the operational status of a target.
    """

    ACTIVE = 'active'
    ARCHIVED = 'archived'
    BLACKLISTED = 'blacklisted'
    VULNERABLE = 'vulnerable'


class Target(BaseModel):
    """
    Represents a specific asset (Target) within a Vault.

    Targets can be hierarchical (e.g., Domain -> Subdomain -> Endpoint)
    """

    __tablename__ = 'targets'

    identifier = Column(String(512), nullable=False, index=True)
    target_type = Column(SaEnum(TargetType), default=TargetType.WEB, nullable=False)

    vault_id = Column(Integer, ForeignKey('vaults.id', ondelete='SET NULL'), nullable=True)
    vault = relationship('Vault', backref=backref('targets', cascade='all, delete-orphan'))

    parent_id = Column(Integer, ForeignKey('targets.id', ondelete='SET NULL'), nullable=True)
    children = relationship(
        'Target',
        cascade = 'all, delete-orphan',
        backref = backref(
            'parent',
            remote_side='Target.id'
        )
    )

    status = Column(SaEnum(TargetStatus), default=TargetStatus.ACTIVE, nullable=False)
    is_wildcard = Column(Boolean, default=False)

    ip_address = Column(String(45), nullable=True)
    tech_stack = Column(JSON, nullable=True)
    risk_score = Column(Integer, default = 0)
    description = Column(Text, nullable=True)
    last_scanned_at = Column(DateTime, nullable=True)


    def __repr__(self) -> str:
        """
        Return text representation.
        """

        return f'<Target "{self.identifier}">'

    def mark_scanned(self) -> None:
        """
        Update the last_scanned_at timestamp.
        """

        self.last_scanned_at = datetime.utcnow()
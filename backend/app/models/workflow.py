import enum

from typing import Optional

from sqlalchemy import (
    Column,
    String,
    Integer,
    ForeignKey,
    Text,
    JSON,
    Enum as SaEnum,
    Boolean,
    DateTime
)

from sqlalchemy.orm import relationship, backref
from app.models.base import BaseModel


class WorkflowStatus(str, enum.Enum):
    """
    Enumeration of workflow execution status.
    """

    DRAFT    = 'draft'
    ACTIVE   = 'active'
    PAUSED   = 'paused'
    ARCHIVED = 'archived'


class Workflow(BaseModel):
    """
    Automated scan workflows (scan chains).
    
    Workflows define multi-step scanning operations.
    Example: Subdomain Enum → DNS Resolution → Port Scan → Vuln Scan
    """
    
    __tablename__ = 'workflows'
    
    name = Column(String(255), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    
    vault_id = Column(Integer, ForeignKey('vaults.id', ondelete='CASCADE'), nullable=True)
    vault = relationship('Vault', backref='workflows')
    
    steps = Column(JSON, nullable=False)
    triggers = Column(JSON, default=list)
    schedule = Column(String(100), nullable=True)
    is_active = Column(Boolean, default=True)
    status = Column(SaEnum(WorkflowStatus), default=WorkflowStatus.DRAFT)
    execution_count = Column(Integer, default=0)
    last_executed_at = Column(DateTime, nullable=True)
    
    def __repr__(self) -> str:
        """
        Text representation of Workflow.
        """
        
        return f'<Workflow {self.name}>'
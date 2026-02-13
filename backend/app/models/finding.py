import enum

from typing import Optional

from sqlalchemy import (
    Column,
    String,
    Integer,
    ForeignKey,
    DateTime,
    JSON,
    Text,
    Enum as SaEnum,
    Boolean
)

from sqlalchemy.orm import relationship, backref
from app.models.base import BaseModel


class Severity(str, enum.Enum):
    """
    Enumeration of finding severity levels.
    """

    INFO     = 'info'
    LOW      = 'low'
    MEDIUM   = 'medium'
    HIGH     = 'high'
    CRITICAL = 'critical'


class FindingStatus(str, enum.Enum):
    """
    Enumeration of finding lifecycle status.
    """

    NEW            = 'new'
    TRIAGING       = 'triaging'
    VALIDATED      = 'validated'
    REPORTED       = 'reported'
    ACCEPTED       = 'accepted'
    RESOLVED       = 'resolved'
    DUPLICATE      = 'duplicate'
    FALSE_POSITIVE = 'false_positive'
    WONT_FIX       = 'wont_fix'


class Finding(BaseModel):
    """
    Represents a discovered vulnerability or security issue.
    """
    
    __tablename__ = 'findings'
    
    scan_id = Column(Integer, ForeignKey('scans.id', ondelete='CASCADE'), nullable=True, index=True)
    scan = relationship('Scan', backref=backref('findings', cascade='all, delete-orphan'))
    
    target_id = Column(Integer, ForeignKey('targets.id', ondelete='CASCADE'), nullable=False, index=True)
    target = relationship('Target', backref=backref('findings', cascade='all, delete-orphan'))
    
    signature_id = Column(Integer, ForeignKey('signatures.id', ondelete='SET NULL'), nullable=True)
    signature = relationship('Signature', backref='findings')
    
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(SaEnum(Severity), default=Severity.INFO, nullable=False, index=True)
    status = Column(SaEnum(FindingStatus), default=FindingStatus.NEW, nullable=False)
    
    cvss_score = Column(String(10), nullable=True)
    cve_id = Column(String(50), nullable=True)
    cwe_id = Column(String(50), nullable=True)
    
    evidence = Column(JSON, default=lambda: {})
    remediation = Column(Text, nullable=True)
    
    affected_url = Column(Text, nullable=True)
    affected_parameter = Column(String(255), nullable=True)
    
    poc = Column(Text, nullable=True)
    
    is_duplicate = Column(Boolean, default=False)
    duplicate_of_id = Column(Integer, ForeignKey('findings.id', ondelete='SET NULL'), nullable=True)
    
    reported_at = Column(DateTime, nullable=True)
    bounty_amount = Column(Integer, nullable=True)
    
    def __repr__(self) -> str:
        """
        Text representation of Finding.
        """
        
        return f'<Finding {self.severity}: {self.title}>'
    
    def mark_false_positive(self) -> None:
        """
        Mark finding as false positive.
        """

        self.status = FindingStatus.FALSE_POSITIVE
    
    def mark_reported(self) -> None:
        """
        Mark finding as reported.
        """
        
        self.status = FindingStatus.REPORTED
        self.reported_at = datetime.utcnow()

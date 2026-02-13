import enum

from typing import Optional
from datetime import datetime

from sqlalchemy import (
    Column,
    String,
    Integer,
    ForeignKey,
    DateTime,
    JSON,
    Text,
    Enum as SaEnum,
    Boolean,
    Index
)

from sqlalchemy.orm import relationship, backref
from app.models.base import BaseModel

class ScanType(str, enum.Enum):
    """
    Enumeration of scan operation types
    """

    SUBDOMAIN_ENUM       = 'subdomain_enumeration'
    JAVASCRIPT_ANALYSIS  = 'javascript_analysis'
    SERVICE_DETECTION    = 'service_detection'
    DNS_RESOLUTION       = 'dns_resolution'
    PORT_SCAN            = 'port_scan'
    WEB_CRAWL            = 'web_crawl'
    TECHNOLOGY_DETECTION = 'technology_detection'
    SSL_ANALYSIS         = 'ssl_analysis'
    VULNERABILITY_SCAN   = 'vulnerability_scan'
    CUSTOM_SIGNATURE     = 'custom_signature'
    FULL_RECON           = 'full_recon'


class ScanStatus(str, enum.Enum):
    """
    Enumeration of scan execution status.
    """

    QUEUED = 'queued'
    RUNNING = 'running'
    PAUSED = 'paused'
    COMPLETED = 'completed'
    CANCELLED = 'cancelled'
    FAILED = 'failed'


class Scan(BaseModel):
    """
    Represents a scan operation execution.
    """

    __tablename__ = 'scans'

    target_id = Column(Integer, ForeignKey('targets.id', ondelete='CASCADE'), nullable=False, index=True)
    target = relationship('Target', backref=backref('scans', cascade='all, delete-orphan'))

    module_id = Column(Integer, ForeignKey('modules.id', ondelete='SET NULL'), nullable=True)
    module = relationship('Module', backref='scans')

    scan_type = Column(SaEnum(ScanType), nullable=False)
    status = Column(SaEnum(ScanStatus), default=ScanStatus.QUEUED, nullable=False)
    
    config = Column(JSON, default=lambda: {})
    result_summary = Column(JSON, default=lambda: {})
    error_message = Column(Text, nullable=True)

    assets_discovered = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)

    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    triggered_by = Column(String(50), default='manual')

    __table_args__ = (
        Index('ix_scan_target_status', 'target_id', 'status'),
        Index('ix_scan_module_type', 'module_id', 'scan_type')
    )

    def __repr__(self) -> None:
        """
        Text representation of Scan.
        """

        return f'<Scan {self.scan_type} - {self.status}>'

    def start(self) -> None:
        """
        Mark scan as started.
        """

        self.status = ScanStatus.RUNNING
        self.started_at = datetime.utcnow()

    def complete(self) -> None:
        """
        Mark scan as completed.
        """

        self.status = ScanStatus.COMPLETED
        self.completed_at = datetime.utcnow()

        if self.started_at:
            delta = self.completed_at - self.started_at
            self.duration_seconds = int(delta.total_seconds())

    def fail(self, error: str) -> None:
        """
        Mark scan as failed.
        """

        self.status = ScanStatus.FAILED
        self.error_message = error
        self.completed_at = datetime.utcnow()

        if self.started_at:
            delta = self.completed_at - self.started_at
            self.duration_seconds = int(delta.total_seconds())

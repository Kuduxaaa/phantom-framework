import enum
import hashlib

from typing import Optional, Dict, Any
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
    Index,
    event
)

from sqlalchemy.orm import relationship, backref
from app.models.base import BaseModel

class AssetType(str, enum.Enum):
    """
    Enumeration of asset types.
    """

    SUBDOMAIN      = 'subdomain'
    IP_ADDRESS     = 'ip_address'
    PORT           = 'port'
    SERVICE        = 'service'
    URL            = 'url'
    ENDPOINT       = 'endpoint'
    PARAMETER      = 'parameter'
    HEADER         = 'header'
    COOKIE         = 'cookie'
    JAVASCRIPT     = 'javascript'
    TECHNOLOGY     = 'technology'
    SSL_CERT       = 'ssl_cert'
    DNS_RECORD     = 'dns_record'
    EMAIL          = 'email'
    CREDENTIAL     = 'credential'
    API_KEY        = 'api_key'
    FORM           = 'form'
    WEBSOCKET      = 'websocket'
    GRAPHQL_SCHEMA = 'graphql_schema'
    S3_BUCKET      = 's3_bucket'
    CLOUD_RESOURCE = 'cloud_resource'

class AssetStatus(str, enum.Enum):
    """
    Enumeration of asset lifecycle status.
    """

    NEW = 'new'
    VERIFIED = 'verified'
    CHANGED = 'changed'
    REMOVED = 'removed'
    MONITORED = 'monitored'

class Asset(BaseModel):
    """
    Universal inteligence storage of ALL discovered data.

    This is the heart of Phantom's inteligence database
    Every piece of discovered information become an Asset
    """

    __tablename__ = 'assets'

    target_id = Column(Integer, ForeignKey('targets.id', ondelete='CASCADE'), nullable=False, index=True)
    target = relationship('Target', backref=backref('assets', cascade='all, delete-orphan'))

    asset_type = Column(SaEnum(AssetType), nullable=False, index=True)
    status = Column(SaEnum(AssetStatus), default=AssetStatus.NEW, nullable=False)
    value = Column(Text, nullable=False)

    asset_metadata = Column(JSON, default=lambda: {})
    asset_source = Column(String(100), nullable=True)
    asset_confidence = Column(Integer, default=100)
    asset_hash = Column(String(64), unique=True, index=True)

    is_active = Column(Boolean, default=True)
    is_sensitive = Column(Boolean, default=False)

    first_seen_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_verified_at = Column(DateTime, nullable=True)

    parent_asset_id = Column(Integer, ForeignKey('assets.id', ondelete='SET NULL'), nullable=True)
    parent = relationship('Asset', remote_side='Asset.id', backref='children')
    
    __table_args__ = (
        Index('ix_asset_target_type', 'target_id', 'asset_type'),
        Index('ix_asset_status', 'status', 'is_active'),
    )

    def __repr__(self) -> str:
        """
        String representation of Asset.
        """

        return f'<Asset {self.asset_type}: {self.value[:50]}>'

    def mark_seen(self) -> None:
        """
        Update last seen timestamp.
        """

        self.last_seen_at = datetime.utcnow()

    def mark_verified(self) -> None:
        """
        Mark asset as verified.
        """

        self.last_verified_at = datetime.utcnow()
        self.status = AssetStatus.VERIFIED

    def mark_changed(self) -> None:
        """
        Mark asset as changed.
        """

        self.status = AssetStatus.CHANGED

    @classmethod
    def create_hash(
        cls,
        target_id: int,
        asset_type: str,
        value: str
    ) -> str:
        """
        Generate unique hash for asset deduplication.

        Args:
            target_id: Target ID
            asset_type: Asset type
            value: Asset value

        Returns:
            SHA256 hash string
        """

        data = f'{target_id}:{asset_type}:{value}'

        return hashlib.sha256(data.encode).hexdigest()

@event.listens_for(Asset, 'before_insert')
def set_asset_hash(mapper, connection, target):
    """
    Auto-generate asset_hash for deduplication if not already set.
    """

    if not target.asset_hash:
        target.asset_hash = Asset.create_hash(
            target_id  = target.target_id,
            asset_type = target.asset_type.value,
            value      = target.value
        )
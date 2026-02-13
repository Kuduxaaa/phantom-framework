import enum

from typing import Optional

from sqlalchemy import (
    Column,
    String,
    Integer,
    Text,
    JSON,
    Enum as SaEnum,
    Boolean,
    Index
)

from app.models.base import BaseModel


class SignatureType(str, enum.Enum):
    """
    Enumeration of signature detection types.
    """

    VULNERABILITY          = 'vulnerability'
    CONFIGURATION          = 'configuration'
    INFORMATION_DISCLOSURE = 'information_disclosure'
    TECHNOLOGY_DETECTION   = 'technology_detection'
    CUSTOM                 = 'custom'


class SignatureLanguage(str, enum.Enum):
    """
    Enumeration of signature template languages.
    """

    YAML = 'yaml'
    JSON = 'json'


class Signature(BaseModel):
    """
    User-editable detection signatures.
    
    Signatures define WHAT to look for and HOW to detect it.
    They can be created, edited, and managed from the dashboard.
    """
    
    __tablename__ = 'signatures'
    
    name = Column(String(255), unique=True, nullable=False, index=True)
    signature_id = Column(String(100), unique=True, nullable=False, index=True)
    signature_type = Column(SaEnum(SignatureType), nullable=False)
    version = Column(String(50), default='1.0', nullable=False)
    author = Column(String(100), nullable=True)
    description = Column(Text, nullable=True)
    icon = Column(String(50), nullable=True)
    severity = Column(String(20), default='info')
    language = Column(SaEnum(SignatureLanguage), default=SignatureLanguage.YAML, nullable=False)
    template = Column(Text, nullable=False)
    matchers = Column(JSON, default=lambda: [])
    extractors = Column(JSON, default=lambda: [])
    references = Column(JSON, default=lambda: [])
    tags = Column(JSON, default=lambda: [])
    
    cve_id = Column(String(50), nullable=True)
    cwe_id = Column(String(50), nullable=True)
    
    is_active = Column(Boolean, default=True, index=True)    
    is_verified = Column(Boolean, default=False)
    false_positive_rate = Column(Integer, default=0)
    execution_count = Column(Integer, default=0)
    success_count = Column(Integer, default=0)
    category = Column(String(100), nullable=True, index=True)
    requires_auth = Column(Boolean, default=False)
    
    signature_metadata = Column(JSON, default=lambda: {})
    
    __table_args__ = (
        Index('ix_signature_type_active', 'signature_type', 'is_active'),
    )
    
    def __repr__(self) -> str:
        """
        Text representation of Signature.
        """
        
        return f'<Signature {self.signature_id} v{self.version}>'
    
    def increment_execution(self) -> None:
        """
        Increment execution counter.
        """
        
        self.execution_count += 1
    
    def increment_success(self) -> None:
        """
        Increment success counter.
        """
        
        self.success_count += 1
    
    def activate(self) -> None:
        """
        Activate signature.
        """
        
        self.is_active = True
    
    def deactivate(self) -> None:
        """
        Deactivate signature.
        """
        
        self.is_active = False
    
    @property
    def success_rate(self) -> int:
        """
        Calculate success rate percentage.
        
        Returns:
            Success rate as integer percentage
        """

        if self.execution_count == 0:
            return 0
        
        return int((self.success_count / self.execution_count) * 100)

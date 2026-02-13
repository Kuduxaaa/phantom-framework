import os

from sqlalchemy import (
    Column,
    String,
    Text,
    Boolean,
    DateTime,
    func
)

from app.config import settings
from app.models.base import BaseModel
from cryptography.fernet import Fernet


SECRET_KEY = os.environ.get(settings.SECRET_KEY, Fernet.generate_key())
fernet = Fernet(SECRET_KEY)


class SystemConfig(BaseModel):
    """
    Dynamic configuration storage for API keys and system settings.
    Supports encryption and automatic timestamping.
    """

    __tablename__ = 'system_configs'

    key = Column(String(255), unique=True, index=True, nullable=False)
    value = Column(Text, nullable=False)
    description = Column(String(500), nullable=True)
    is_encrypted = Column(Boolean, default=False)
    group = Column(String(100), default='general')

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    def __repr__(self) -> str:
        return f'<SystemConfig {self.key}>'

    def set_value(
        self, 
        raw_value: str, 
        encrypt: bool = False
    ) -> None:
        """
        Set the value and optionally encrypt it.
        """

        if encrypt:
            self.value = fernet.encrypt(raw_value.encode()).decode()
            self.is_encrypted = True
        else:
            self.value = raw_value
            self.is_encrypted = False

    def get_value(self) -> str:
        """
        Return decrypted value if needed.
        """

        if self.is_encrypted:
            return fernet.decrypt(self.value.encode()).decode()
        
        return self.value

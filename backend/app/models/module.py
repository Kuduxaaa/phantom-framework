import enum

from typing import Optional

from sqlalchemy import (
    Column,
    String,
    Integer,
    Text,
    JSON,
    Enum as SaEnum,
    Boolean
)

from app.models.base import BaseModel


class ModuleType(str, enum.Enum):
    """
    Enumeration of module category types.
    """
    
    RECONNAISSANCE = 'reconnaissance'
    VULNERABILITY  = 'vulnerability'
    EXPLOITATION   = 'exploitation'
    INTELLIGENCE   = 'intelligence'
    NETWORK        = 'network'
    UTILITY        = 'utility'
    CUSTOM         = 'custom'
    WEB            = 'web'


class ModuleStatus(str, enum.Enum):
    """
    Enumeration of module operational status.
    """

    ACTIVE = 'active'
    INACTIVE = 'inactive'
    DEPRECATED = 'deprecated'
    TESTING = 'testing'


class Module(BaseModel):
    """
    Represents a reusable scanner module.
    
    Modules are the building blocks of Phantom's scanning engine.
    They can be chained, configured, and dynamically loaded.
    """
    
    __tablename__ = 'modules'
    
    name = Column(String(255), unique=True, nullable=False, index=True)
    display_name = Column(String(255), nullable=False)
    module_type = Column(SaEnum(ModuleType), nullable=False)
    version = Column(String(50), nullable=False)
    description = Column(Text, nullable=True)
    author = Column(String(100), nullable=True)
    icon = Column(String(50), nullable=True)
    python_class = Column(String(255), nullable=False)
    default_config = Column(JSON, default=lambda: {})
    required_config = Column(JSON, default=lambda: [])
    outputs = Column(JSON, default=lambda: [])
    dependencies = Column(JSON, default=lambda: [])
    tags = Column(JSON, default=lambda: [])
    is_active = Column(Boolean, default=True)
    status = Column(SaEnum(ModuleStatus), default=ModuleStatus.ACTIVE)
    execution_count = Column(Integer, default=0)
    average_duration = Column(Integer, default=0)
    success_rate = Column(Integer, default=100, nullable=False) # 0 - 100
    documentation_url = Column(String(500), nullable=True)
    
    def __repr__(self) -> str:
        """
        Text representation of Module.
        """

        return f'<Module {self.name} v{self.version}>'
    
    def increment_execution(self) -> None:
        """
        Increment execution counter.
        """
        
        self.execution_count += 1
    
    def activate(self) -> None:
        """
        Activate module.
        """
        
        self.is_active = True
        self.status = ModuleStatus.ACTIVE
    
    def deactivate(self) -> None:
        """
        Deactivate module.
        """
        
        self.is_active = False
        self.status = ModuleStatus.INACTIVE

    def record_execution(self, duration: int, success: bool) -> None:
        """
        Record a module execution result.
        """

        self.execution_count += 1

        self.average_duration = int(
            (self.average_duration * (self.execution_count - 1) + duration)
            / self.execution_count
        )

        if success:
            self.success_rate = min(100, self.success_rate + 1)
        else:
            self.success_rate = max(0, self.success_rate - 1)

import enum
import fnmatch

from typing import List, Union
from sqlalchemy import (
    Column, 
    String, 
    JSON, 
    Enum as SaEnum
)

from sqlalchemy.orm import relationship
from app.models.base import BaseModel

class PlatformType(str, enum.Enum):
    """
    Enum representing supported bug bounty platforms.
    """
    
    HACKERONE = 'hackerone'
    BUGCROWD  = 'bugcrowd'
    INTIGRITI = 'intigriti'
    YESWEHACK = 'yeswehack'
    CUSTOM    = 'custom'


class Vault(BaseModel):
    """
    Represents a Bug Bounty Program vault.

    Each vault may have multiple research entries associated with it.
    Scope rules are defined as JSON with "in" and "out" patterns.
    """

    __tablename__ = 'vaults'

    name = Column(String(255), nullable=False, index=True)
    platform = Column(SaEnum(PlatformType), default=PlatformType.CUSTOM, nullable=False)
    target_domain = Column(String(255), nullable=False)

    program_url = Column(String(255), nullable=True) # TODO: We can automaticlly fetch in/out scope patterns, policy or rules using API.
    scope_rules = Column(JSON, nullable=False) # TODO: We using system casted JSON. Sample: {"in": ["*.example.com", "*.example.ge"], "out": "dev.example.com"}

    def __repr__(self) -> str:
        """
        Return developer-friendly representation.
        """
        
        return f'<Vault {self.name} ({self.platform})>'

    def __str__(self) -> str:
        """
        Return user-friendly representation.
        """
        
        return f'<Vault "{self.name}" on {self.platform}>'

    def is_in_scope(self, domain: str) -> bool:
        """
        Check if a domain is considered in-scope for this vault.

        Args:
            domain (str): The domain to check.

        Returns:
            bool: True if the domain matches in-scope rules and is not
                explicitly out-of-scope, False otherwise.

        Notes:
            Supports wildcard patterns using fnmatch (e.g., '*.example.com').
            Out-of-scope patterns override in-scope patterns.
        """

        in_patterns: Union[List[str], str] = self.scope_rules.get('in', [])
        out_patterns: Union[List[str], str] = self.scope_rules.get('out', [])

        if isinstance(in_patterns, str):
            in_patterns = [in_patterns]

        if isinstance(out_patterns, str):
            out_patterns = [out_patterns]

        for pattern in out_patterns:
            if fnmatch.fnmatch(domain, pattern):
                return False

        for pattern in in_patterns:
            if fnmatch.fnmatch(domain, pattern):
                return True

        return False

    def is_out_scope(self, domain: str) -> bool:
        """
        Check if a domain is explicitly out-of-scope.

        Args:
            domain (str): The domain to check.

        Returns:
            bool: True if the domain is out-of-scope, False otherwise.
        """

        return not self.is_in_scope(domain)

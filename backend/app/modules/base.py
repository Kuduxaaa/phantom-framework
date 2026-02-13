from abc import ABC, abstractmethod

from typing import Dict, Any


class BaseModule(ABC):
    """
    Abstract base class for all modules.
    """

    def __init__(self, **kwargs):
        self.config = kwargs
        self.results: Dict[str, Any] = {}
    
    @abstractmethod
    async def execute(self) -> Dict[str, Any]:
        """
        Execute the module's main functionality.
        
        Returns:
            Module execution results
        """

        pass
    
    @abstractmethod
    async def validate(self) -> bool:
        """
        Validate module prerequisites.
        
        Returns:
            True if validation passes
        """

        pass
    
    def get_results(self) -> Dict[str, Any]:
        """
        Get module execution results.
        
        Returns:
            Results dictionary
        """

        return self.results

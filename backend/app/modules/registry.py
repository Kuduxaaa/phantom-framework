from app.modules.base import BaseModule

from typing import Dict, Type


class ModuleRegistry:
    """
    Registry for dynamic module loading.
    """

    _modules: Dict[str, Type[BaseModule]] = {}
    
    @classmethod
    def register(cls, name: str):
        """
        Decorator to register a module.
        
        Args:
            name: Module identifier
            
        Returns:
            Decorator function
        """

        def decorator(module_class: Type[BaseModule]):
            cls._modules[name] = module_class
            
            return module_class
        
        return decorator
    
    @classmethod
    def get(cls, name: str) -> Type[BaseModule]:
        """
        Get module class by name.
        
        Args:
            name: Module identifier
            
        Returns:
            Module class
            
        Raises:
            KeyError: If module not found
        """

        if name not in cls._modules:
            raise KeyError(f'Module "{name}" not found in registry')
        
        return cls._modules[name]
    
    @classmethod
    def list_modules(cls) -> Dict[str, Type[BaseModule]]:
        """
        List all registered modules.
        
        Returns:
            Dictionary of module names to classes
        """

        return cls._modules.copy()

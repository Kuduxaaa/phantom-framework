from typing import Callable, Dict, List, Any


class EventBus:
    """
    Simple event bus for pub/sub pattern.
    """

    _subscribers: Dict[str, List[Callable]] = {}
    
    @classmethod
    def subscribe(cls, event: str, callback: Callable):
        """
        Subscribe to an event.
        
        Args:
            event: Event name
            callback: Callback function
        """

        if event not in cls._subscribers:
            cls._subscribers[event] = []
        
        cls._subscribers[event].append(callback)
    
    @classmethod
    async def publish(cls, event: str, data: Any):
        """
        Publish an event to all subscribers.
        
        Args:
            event: Event name
            data: Event data
        """

        if event not in cls._subscribers:
            return
        
        for callback in cls._subscribers[event]:
            if callable(callback):
                await callback(data)
    
    @classmethod
    def clear(cls, event: str = None):
        """
        Clear subscribers for an event or all events.
        
        Args:
            event: Event name (None = clear all)
        """

        if event:
            cls._subscribers.pop(event, None)

        else:
            cls._subscribers.clear()

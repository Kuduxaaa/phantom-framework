"""
Data movement: chunked HTTP streaming and WebSocket tunneling.
"""

from app.core.proxy.transport.streamer import stream_body
from app.core.proxy.transport.websocket import is_websocket_upgrade, tunnel

__all__ = [
    'stream_body',
    'is_websocket_upgrade',
    'tunnel',
]

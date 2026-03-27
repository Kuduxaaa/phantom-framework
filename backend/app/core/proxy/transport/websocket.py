import asyncio
from typing import Any

import aiohttp
from aiohttp import web, WSMsgType


def is_websocket_upgrade(request: web.Request) -> bool:
    """
    Detect whether the inbound request is a WebSocket upgrade.
    """

    upgrade    = request.headers.get('Upgrade', '').lower()
    connection = request.headers.get('Connection', '').lower()

    return upgrade == 'websocket' and 'upgrade' in connection


async def _forward_ws(
    source:      Any,
    destination: Any,
) -> None:
    """
    Forward messages from one WebSocket peer to the other.
    """

    async for msg in source:
        if msg.type == WSMsgType.TEXT:
            await destination.send_str(msg.data)

        elif msg.type == WSMsgType.BINARY:
            await destination.send_bytes(msg.data)

        elif msg.type == WSMsgType.PING:
            await destination.ping(msg.data)

        elif msg.type == WSMsgType.PONG:
            await destination.pong(msg.data)

        elif msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.CLOSED):
            break

        elif msg.type == WSMsgType.ERROR:
            break


async def tunnel(
    client_ws:   web.WebSocketResponse,
    upstream_ws: aiohttp.ClientWebSocketResponse,
) -> None:
    """
    Establish a bidirectional WebSocket tunnel.

    Runs two forwarding tasks in parallel. When either side closes,
    the other task is cancelled.
    """

    client_to_upstream = asyncio.create_task(
        _forward_ws(client_ws, upstream_ws)
    )

    upstream_to_client = asyncio.create_task(
        _forward_ws(upstream_ws, client_ws)
    )

    done, pending = await asyncio.wait(
        [client_to_upstream, upstream_to_client],
        return_when=asyncio.FIRST_COMPLETED,
    )

    for task in pending:
        task.cancel()

    for task in done:
        try:
            task.result()
        except Exception:
            pass

    for task in pending:
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

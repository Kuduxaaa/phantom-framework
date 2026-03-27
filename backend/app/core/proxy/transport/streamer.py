from typing import Any

from aiohttp import web

from app.core.proxy.constants import BUFFER_SIZE


async def stream_body(
    source:      Any,
    destination: web.StreamResponse,
) -> None:
    """
    Stream the response body from upstream to the client in 64 KB chunks.
    """

    while True:
        chunk = await source.content.read(BUFFER_SIZE)

        if not chunk:
            break

        await destination.write(chunk)

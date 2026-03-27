import asyncio
import logging

from typing import Callable

from aiohttp import web, ClientSession, TCPConnector

from app.core.proxy.config import ProxySettings
from app.core.proxy.constants import SERVER_SIGNATURE
from app.core.proxy.handler import ProxyHandler

logger = logging.getLogger('ph-proxy.server')


@web.middleware
async def _server_header_middleware(
    request: web.Request,
    handler: Callable,
) -> web.StreamResponse:
    response = await handler(request)
    response.headers['Server'] = SERVER_SIGNATURE
    return response


async def _on_startup(app: web.Application) -> None:
    connector = TCPConnector(
        ssl=False,
        force_close=True,
    )

    app['client_session'] = ClientSession(
        connector=connector,
        auto_decompress=False,
    )


async def _on_cleanup(app: web.Application) -> None:
    await app['client_session'].close()


def create_proxy_app(settings: ProxySettings) -> web.Application:
    """
    Build an aiohttp Application configured as a forward proxy.
    """

    app = web.Application(middlewares=[_server_header_middleware])

    async def on_startup_handler(app: web.Application) -> None:
        await _on_startup(app)

        handler = ProxyHandler(
            settings=settings,
            session=app['client_session'],
        )

        app['proxy_handler'] = handler

    app.on_startup.append(on_startup_handler)
    app.on_cleanup.append(_on_cleanup)

    app.router.add_route('*', '/{path_info:.*}', _proxy_dispatch)

    return app


async def _proxy_dispatch(request: web.Request) -> web.StreamResponse:
    handler: ProxyHandler = request.app['proxy_handler']
    return await handler.handle(request)


async def _serve(settings: ProxySettings) -> None:
    app    = create_proxy_app(settings)
    runner = web.AppRunner(app, handle_signals=False)
    await runner.setup()

    try:
        site = web.TCPSite(runner, '0.0.0.0', settings.port)
        await site.start()
        logger.info('ph-proxy listening on port %d', settings.port)

        await asyncio.Event().wait()
    finally:
        await runner.cleanup()


def run(port: int = 8080, **kwargs) -> None:
    """
    Start ph-proxy as a forward proxy.
    """

    settings = ProxySettings(port=port, **kwargs)

    try:
        asyncio.run(_serve(settings))
    except KeyboardInterrupt:
        logger.info('ph-proxy shutdown complete')

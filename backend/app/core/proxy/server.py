import asyncio
import logging

from aiohttp import web

from app.core.proxy.certs import CertManager
from app.core.proxy.config import ProxySettings
from app.core.proxy.handler import ProxyHandler

logger = logging.getLogger('ph-proxy.server')


async def _serve(settings: ProxySettings, verbose: bool = False) -> None:
    certs   = CertManager()
    handler = ProxyHandler(settings, verbose=verbose, certs=certs)
    await handler.start()

    server = web.Server(handler.handle)
    runner = web.ServerRunner(server)
    await runner.setup()

    try:
        site = web.TCPSite(runner, '0.0.0.0', settings.port)
        await site.start()

        logger.info('ph-proxy listening on port %d', settings.port)
        logger.info('CA certificate: %s', certs.ca_cert_path)
        logger.info('Install the CA in your browser/system to inspect HTTPS traffic')

        await asyncio.Event().wait()
    finally:
        await handler.stop()
        await runner.cleanup()


def run(port: int = 8080, verbose: bool = False, **kwargs) -> None:
    """
    Start ph-proxy as a forward intercepting proxy with MITM support.
    """

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    )

    settings = ProxySettings(port=port, **kwargs)

    try:
        asyncio.run(_serve(settings, verbose=verbose))
    except KeyboardInterrupt:
        logger.info('ph-proxy shutdown complete')

import asyncio
import logging
import ssl

import aiohttp
from aiohttp import web, ClientSession, ClientTimeout

from app.core.proxy.config import ProxySettings
from app.core.proxy.constants import BUFFER_SIZE, SERVER_SIGNATURE
from app.core.proxy.errors import bad_gateway, gateway_timeout
from app.core.proxy.headers import strip_hop_by_hop
from app.core.proxy.transport import stream_body, is_websocket_upgrade, tunnel

logger = logging.getLogger('ph-proxy.handler')


class ProxyHandler:
    """
    Forward proxy handler for Phantom Framework.

    Accepts HTTP requests with absolute URLs and forwards them to the
    target server. Supports CONNECT tunneling for HTTPS and WebSocket
    upgrade proxying.
    """

    def __init__(
        self,
        settings: ProxySettings,
        session:  ClientSession,
    ) -> None:
        self._settings = settings
        self._session  = session

        self._ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode    = ssl.CERT_NONE

    async def handle(self, request: web.Request) -> web.StreamResponse:
        """
        Handle an incoming proxy request.

        Routes to CONNECT tunneling for HTTPS or forwards the
        full-URL HTTP request to the target.
        """

        if request.method == 'CONNECT':
            return await self._handle_connect(request)

        if is_websocket_upgrade(request):
            return await self._handle_websocket(request)

        return await self._handle_http(request)

    async def _handle_http(
        self,
        request: web.Request,
    ) -> web.StreamResponse:
        """
        Forward an HTTP request to the target URL and stream the response.
        """

        target_url = str(request.url)
        headers    = strip_hop_by_hop(request.headers)

        timeout = ClientTimeout(
            connect=self._settings.connect_timeout,
            sock_read=self._settings.read_timeout,
            total=self._settings.total_timeout,
        )

        try:
            upstream_resp = await self._session.request(
                method=request.method,
                url=target_url,
                headers=headers,
                data=request.content,
                timeout=timeout,
                ssl=self._ssl_ctx,
            )
        except asyncio.TimeoutError:
            return gateway_timeout('Upstream timed out')
        except aiohttp.ClientConnectorError as exc:
            logger.warning('Cannot connect to %s: %s', target_url, exc)
            return bad_gateway('Cannot connect to upstream')
        except Exception as exc:
            logger.exception('Unexpected upstream error: %s', exc)
            return bad_gateway()

        response_headers = strip_hop_by_hop(upstream_resp.headers)
        response_headers.pop('Content-Length', None)

        response = web.StreamResponse(
            status=upstream_resp.status,
            reason=upstream_resp.reason,
            headers=response_headers,
        )

        response.headers['Server'] = SERVER_SIGNATURE

        try:
            await response.prepare(request)
            await stream_body(upstream_resp, response)
        except asyncio.TimeoutError:
            logger.warning('Read timeout streaming from %s', target_url)
        except Exception as exc:
            logger.warning('Streaming interrupted for %s: %s', target_url, exc)
        finally:
            upstream_resp.close()

        try:
            await response.write_eof()
        except Exception:
            pass

        return response

    async def _handle_connect(
        self,
        request: web.Request,
    ) -> web.StreamResponse:
        """
        Handle CONNECT method for HTTPS tunneling.

        Establishes a raw TCP tunnel between the client and the
        upstream server. Replaces the aiohttp protocol on the client
        transport to bridge bidirectional data at the TCP level.
        """

        target_host = request.host
        if ':' in target_host:
            host, port_str = target_host.rsplit(':', 1)
            port = int(port_str)
        else:
            host = target_host
            port = 443

        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self._settings.connect_timeout,
            )
        except (asyncio.TimeoutError, OSError) as exc:
            logger.warning('CONNECT failed to %s:%d: %s', host, port, exc)
            return bad_gateway(f'Cannot connect to {host}:{port}')

        transport = request.transport
        if transport is None:
            upstream_writer.close()
            return bad_gateway('Client transport unavailable')

        # Send 200 directly via transport, bypassing aiohttp's
        # response pipeline so we can take over the raw connection.
        transport.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')

        # Replace the protocol so client data flows to upstream.
        class _TunnelProtocol(asyncio.Protocol):
            def __init__(self, writer):
                self._writer = writer

            def data_received(self, data: bytes):
                self._writer.write(data)

            def connection_lost(self, exc):
                if not self._writer.is_closing():
                    self._writer.close()

        tunnel_proto = _TunnelProtocol(upstream_writer)
        transport.set_protocol(tunnel_proto)

        # Upstream → client pipe: read from upstream, write to client.
        try:
            while True:
                data = await upstream_reader.read(BUFFER_SIZE)
                if not data:
                    break
                transport.write(data)
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        finally:
            if not upstream_writer.is_closing():
                upstream_writer.close()
            transport.close()

        # Return a dummy response. The transport is already closed,
        # so aiohttp won't actually send this.
        return web.Response()

    async def _handle_websocket(
        self,
        request: web.Request,
    ) -> web.WebSocketResponse:
        """
        Proxy a WebSocket upgrade through a bidirectional tunnel.
        """

        client_ws = web.WebSocketResponse()
        await client_ws.prepare(request)

        target_url = str(request.url)
        ws_url = target_url.replace('http://', 'ws://').replace('https://', 'wss://')

        headers = strip_hop_by_hop(request.headers)

        try:
            upstream_ws = await self._session.ws_connect(
                url=ws_url,
                headers=headers,
                ssl=self._ssl_ctx,
            )
        except Exception as exc:
            logger.exception('WebSocket upstream connect failed: %s', exc)
            await client_ws.close()
            return client_ws

        try:
            await tunnel(client_ws, upstream_ws)
        finally:
            for ws in (upstream_ws, client_ws):
                try:
                    await ws.close()
                except Exception:
                    pass

        return client_ws

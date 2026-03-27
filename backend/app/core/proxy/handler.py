import asyncio
import logging
import ssl

import aiohttp
from aiohttp import web, ClientSession, ClientTimeout, TCPConnector

from app.core.proxy.certs import CertManager
from app.core.proxy.config import ProxySettings
from app.core.proxy.constants import BUFFER_SIZE, SERVER_SIGNATURE
from app.core.proxy.errors import bad_gateway, gateway_timeout
from app.core.proxy.headers import strip_hop_by_hop
from app.core.proxy.transport import stream_body, is_websocket_upgrade, tunnel

logger = logging.getLogger('ph-proxy.handler')


class ProxyHandler:
    """
    Forward intercepting proxy with MITM TLS support.

    Uses web.Server (raw handler) instead of web.Application routing,
    because aiohttp's URL router strips absolute URIs and cannot
    handle CONNECT authority-form requests.

    CONNECT requests are handled with MITM: the proxy terminates TLS
    using an on-the-fly generated certificate, reads the decrypted
    HTTP traffic, logs it, and forwards it to the upstream over a
    real TLS connection.
    """

    def __init__(
        self,
        settings: ProxySettings,
        verbose:  bool = False,
        certs:    CertManager = None,
    ) -> None:
        self._settings = settings
        self._verbose  = verbose
        self._certs    = certs or CertManager()
        self._session: ClientSession = None

        self._ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode    = ssl.CERT_NONE

    async def start(self) -> None:
        connector = TCPConnector(ssl=False, force_close=True)
        self._session = ClientSession(
            connector=connector,
            auto_decompress=False,
        )

    async def stop(self) -> None:
        if self._session:
            await self._session.close()

    async def handle(self, request: web.BaseRequest) -> web.StreamResponse:
        if request.method == 'CONNECT':
            return await self._handle_connect(request)

        if is_websocket_upgrade(request):
            return await self._handle_websocket(request)

        return await self._handle_http(request)

    # ── HTTP forwarding ───────────────────────────────────────

    async def _handle_http(
        self,
        request: web.BaseRequest,
    ) -> web.StreamResponse:
        raw_path = request.path_qs
        host     = request.host

        if raw_path.startswith('http://') or raw_path.startswith('https://'):
            target_url = raw_path
        elif host:
            target_url = f'http://{host}{raw_path}'
        else:
            return web.Response(status=400, text='Missing Host header')

        headers = strip_hop_by_hop(request.headers)

        if self._verbose:
            self._log_request(request, target_url)

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
                allow_redirects=False,
            )
        except asyncio.TimeoutError:
            logger.info('%s %s -> 504 (timeout)', request.method, target_url)
            return gateway_timeout('Upstream timed out')
        except aiohttp.ClientConnectorError as exc:
            logger.info('%s %s -> 502 (%s)', request.method, target_url, exc)
            return bad_gateway('Cannot connect to upstream')
        except Exception as exc:
            logger.info('%s %s -> 502 (error)', request.method, target_url)
            logger.debug('Upstream error: %s', exc, exc_info=True)
            return bad_gateway()

        logger.info('%s %s -> %d', request.method, target_url, upstream_resp.status)

        if self._verbose:
            self._log_response(upstream_resp)

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
        except Exception:
            pass
        finally:
            upstream_resp.close()

        try:
            await response.write_eof()
        except Exception:
            pass

        return response

    # ── CONNECT / MITM ────────────────────────────────────────

    async def _handle_connect(
        self,
        request: web.BaseRequest,
    ) -> web.StreamResponse:
        host, port = self._parse_connect_target(request)
        if not host:
            return web.Response(status=400, text='Invalid CONNECT target')

        # Connect to the real upstream over TLS
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=self._ssl_ctx),
                timeout=self._settings.connect_timeout,
            )
        except (asyncio.TimeoutError, OSError) as exc:
            logger.info('CONNECT %s:%d -> 502 (%s)', host, port, exc)
            return bad_gateway(f'Cannot connect to {host}:{port}')

        transport = request.transport
        if transport is None:
            upstream_writer.close()
            return bad_gateway('Client transport unavailable')

        # Send 200 BEFORE TLS upgrade — the client waits for this
        # before sending the TLS ClientHello.
        transport.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        await asyncio.sleep(0)  # flush write buffer

        # TLS upgrade on the existing transport using the current protocol.
        # loop.start_tls() wraps the transport at the protocol level —
        # no socket detach/dup needed, works on Windows ProactorEventLoop.
        mitm_ctx = self._certs.get_context(host)
        protocol = transport.get_protocol()
        loop = asyncio.get_event_loop()

        try:
            new_transport = await loop.start_tls(
                transport, protocol, mitm_ctx,
                server_side=True,
                ssl_handshake_timeout=10.0,
            )
        except Exception as exc:
            logger.info('CONNECT %s:%d -> TLS handshake failed (%s)', host, port, exc)
            transport.close()
            upstream_writer.close()
            return web.Response()

        # AFTER the handshake, swap to a StreamReaderProtocol so we
        # can read/write decrypted HTTP through asyncio streams.
        client_reader = asyncio.StreamReader()
        client_protocol = asyncio.StreamReaderProtocol(client_reader)
        new_transport.set_protocol(client_protocol)
        client_protocol.connection_made(new_transport)
        client_writer = asyncio.StreamWriter(
            new_transport, client_protocol, client_reader, loop,
        )

        logger.info('CONNECT %s:%d -> MITM tunnel established', host, port)

        await self._proxy_mitm(
            client_reader, client_writer,
            upstream_reader, upstream_writer,
            host,
        )

        return web.Response()

    async def _proxy_mitm(
        self,
        client_reader,   client_writer,
        upstream_reader,  upstream_writer,
        host: str,
    ) -> None:
        """
        Proxy decrypted HTTP/1.1 traffic between client and upstream,
        logging each request and response.
        """

        try:
            while True:
                # ── Request from client ───────────────────────
                req_line = await client_reader.readline()
                if not req_line or req_line == b'\r\n':
                    break

                req_headers_raw = []
                content_length  = 0

                while True:
                    line = await client_reader.readline()
                    if not line or line == b'\r\n':
                        break
                    req_headers_raw.append(line)
                    hl = line.decode('latin-1').lower()
                    if hl.startswith('content-length:'):
                        content_length = int(hl.split(':', 1)[1].strip())

                req_str = req_line.decode('latin-1').strip()

                if self._verbose:
                    parts = [f'  >> {req_str}']
                    for h in req_headers_raw:
                        parts.append(f'  >> {h.decode("latin-1").strip()}')
                    parts.append('  >>')
                    logger.info('\n'.join(parts))

                # Forward request to upstream
                upstream_writer.write(req_line)
                for h in req_headers_raw:
                    upstream_writer.write(h)
                upstream_writer.write(b'\r\n')

                if content_length > 0:
                    body = await client_reader.readexactly(content_length)
                    upstream_writer.write(body)

                await upstream_writer.drain()

                # ── Response from upstream ────────────────────
                resp_line = await upstream_reader.readline()
                if not resp_line:
                    break

                resp_str = resp_line.decode('latin-1').strip()

                resp_headers_raw    = []
                resp_content_length = -1
                chunked             = False
                conn_close          = False

                while True:
                    line = await upstream_reader.readline()
                    if not line or line == b'\r\n':
                        break
                    resp_headers_raw.append(line)
                    hl = line.decode('latin-1').lower()
                    if hl.startswith('content-length:'):
                        resp_content_length = int(hl.split(':', 1)[1].strip())
                    elif hl.startswith('transfer-encoding:') and 'chunked' in hl:
                        chunked = True
                    elif hl.startswith('connection:') and 'close' in hl:
                        conn_close = True

                # Parse status code for body detection
                status_code = 0
                try:
                    status_code = int(resp_str.split(' ', 2)[1])
                except (IndexError, ValueError):
                    pass

                logger.info('%s (via %s) -> %s', req_str, host, resp_str)

                if self._verbose:
                    parts = [f'  << {resp_str}']
                    for h in resp_headers_raw:
                        parts.append(f'  << {h.decode("latin-1").strip()}')
                    parts.append('  <<')
                    logger.info('\n'.join(parts))

                # Forward response headers to client
                client_writer.write(resp_line)
                for h in resp_headers_raw:
                    client_writer.write(h)
                client_writer.write(b'\r\n')

                # Forward response body
                has_body = status_code >= 200 and status_code not in (204, 304)

                if has_body and chunked:
                    while True:
                        size_line = await upstream_reader.readline()
                        client_writer.write(size_line)
                        try:
                            chunk_size = int(size_line.strip(), 16)
                        except ValueError:
                            break
                        if chunk_size == 0:
                            trailer = await upstream_reader.readline()
                            client_writer.write(trailer)
                            break
                        chunk_data = await upstream_reader.readexactly(chunk_size + 2)
                        client_writer.write(chunk_data)

                elif has_body and resp_content_length > 0:
                    body = await upstream_reader.readexactly(resp_content_length)
                    client_writer.write(body)

                elif has_body and resp_content_length == -1 and not chunked:
                    # No length, no chunked — read until upstream closes
                    while True:
                        data = await upstream_reader.read(BUFFER_SIZE)
                        if not data:
                            break
                        client_writer.write(data)
                    conn_close = True

                await client_writer.drain()

                if conn_close:
                    break

        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError,
                asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            for w in (client_writer, upstream_writer):
                try:
                    w.close()
                except Exception:
                    pass

    # ── WebSocket ─────────────────────────────────────────────

    async def _handle_websocket(
        self,
        request: web.BaseRequest,
    ) -> web.WebSocketResponse:
        client_ws = web.WebSocketResponse()
        await client_ws.prepare(request)

        raw_path = request.path_qs
        host     = request.host

        if raw_path.startswith('http://') or raw_path.startswith('https://'):
            target_url = raw_path
        elif host:
            target_url = f'http://{host}{raw_path}'
        else:
            await client_ws.close()
            return client_ws

        ws_url  = target_url.replace('http://', 'ws://').replace('https://', 'wss://')
        headers = strip_hop_by_hop(request.headers)

        try:
            upstream_ws = await self._session.ws_connect(
                url=ws_url, headers=headers, ssl=self._ssl_ctx,
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

    # ── Helpers ───────────────────────────────────────────────

    def _parse_connect_target(self, request):
        target = request.host
        if not target:
            target = str(request.url).strip('/')

        if ':' in target:
            host, port_str = target.rsplit(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                return target, 443
        else:
            host, port = target, 443

        return host, port

    def _log_request(self, request, target_url):
        parts = [f'  >> {request.method} {target_url} HTTP/{request.version.major}.{request.version.minor}']
        for name, value in request.headers.items():
            parts.append(f'  >> {name}: {value}')
        parts.append('  >>')
        logger.info('\n'.join(parts))

    def _log_response(self, resp):
        parts = [f'  << HTTP {resp.status} {resp.reason}']
        for name, value in resp.headers.items():
            parts.append(f'  << {name}: {value}')
        parts.append('  <<')
        logger.info('\n'.join(parts))

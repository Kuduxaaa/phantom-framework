from aiohttp import web


def bad_request(reason: str = 'Bad Request') -> web.Response:
    return web.Response(status=400, text=reason)


def bad_gateway(reason: str = 'Bad Gateway') -> web.Response:
    return web.Response(status=502, text=reason)


def gateway_timeout(reason: str = 'Gateway Timeout') -> web.Response:
    return web.Response(status=504, text=reason)

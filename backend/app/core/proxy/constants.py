BUFFER_SIZE = 65536

CONNECT_TIMEOUT = 5.0
READ_TIMEOUT    = 30.0
TOTAL_TIMEOUT   = 300.0

DEFAULT_PROXY_PORT = 8080

SERVER_SIGNATURE = 'PhProxy'

HOP_BY_HOP_HEADERS = frozenset({
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailers',
    'transfer-encoding',
    'upgrade',
})

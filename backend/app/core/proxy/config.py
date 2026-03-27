from dataclasses import dataclass

from app.core.proxy.constants import (
    CONNECT_TIMEOUT,
    READ_TIMEOUT,
    TOTAL_TIMEOUT,
    DEFAULT_PROXY_PORT,
)


@dataclass
class ProxySettings:
    """
    Configuration for the ph-proxy forward proxy.
    """

    port:            int   = DEFAULT_PROXY_PORT
    connect_timeout: float = CONNECT_TIMEOUT
    read_timeout:    float = READ_TIMEOUT
    total_timeout:   float = TOTAL_TIMEOUT

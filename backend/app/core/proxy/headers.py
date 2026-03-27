from typing import Union

from multidict import CIMultiDict, CIMultiDictProxy

from app.core.proxy.constants import HOP_BY_HOP_HEADERS


def strip_hop_by_hop(
    headers: Union[CIMultiDict[str], CIMultiDictProxy[str]],
) -> CIMultiDict[str]:
    """
    Return a new CIMultiDict with hop-by-hop headers removed.
    """

    return CIMultiDict(
        (key, value)
        for key, value in headers.items()
        if key.lower() not in HOP_BY_HOP_HEADERS
    )

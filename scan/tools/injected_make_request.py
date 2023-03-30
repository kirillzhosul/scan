"""
    Injects custom make request to HTTPConnectionPool, for getting raw peer with socket.
"""

from requests.packages.urllib3.connectionpool import HTTPConnectionPool


def inject_custom_make_request() -> None:
    """
    Injects custom `make_request`.
    """
    HTTPConnectionPool._native_make_request = HTTPConnectionPool._make_request
    HTTPConnectionPool._make_request = _injected_make_request


def get_peer_from_request(req) -> tuple[str, int] | tuple[None, None]:
    """
    Returns peer (ip:port) from request that has injector.
    """
    return req.raw._original_response.peer[:2]


def _injected_make_request(self, connection, method, url, **kwargs) -> ...:
    """
    Custom `_make_request` that includes socket
    """
    response = self._native_make_request(connection, method, url, **kwargs)
    sock = getattr(connection, "sock", False)
    if sock:
        setattr(response, "peer", sock.getpeername())
    else:
        setattr(response, "peer", (None, None))
    return response

"""
    HTTP scan tools and wrappers.
"""
from requests import request, Response, RequestException

from .injected_make_request import inject_custom_make_request

HTTP_USER_AGENT = ""
HTTP_METHODS = [
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "CONNECT",
    "OPTIONS",
    "TRACE",
    "PATCH",
    "*ANY*",
]


def make_request(http_method: str, http_host: str, is_https: bool) -> Response:
    """
    Makes request somehow wrapped for HTTP/S.
    """
    if http_host.startswith("http"):
        http_host = http_host.removeprefix("https://").removeprefix("http://")

    url = f"https://{http_host}" if is_https else f"http://{http_host}"

    return request(
        method=http_method,
        url=url,
        headers={"User-Agent": HTTP_USER_AGENT},
    )


def safe_make_request(http_method: str, http_host: str, is_https: bool) -> Response:
    """
    Makes request somehow wrapped for HTTP/S without failing if any error occurs.
    """
    try:
        return make_request(
            http_method=http_method, http_host=http_host, is_https=is_https
        )
    except RequestException:
        return None


def get_allowed_http_methods(http_host: str) -> list[str]:
    """
    Returns list of allowed HTTP methods on given HTTP host.
    """
    allowed_methods = []
    for method in HTTP_METHODS:
        req = safe_make_request(http_method=method, http_host=http_host, is_https=False)
        if req and req.status_code == 200:
            allowed_methods.append(method)
    return allowed_methods


def get_https_settings(http_host: str) -> tuple[bool, bool, bool]:
    """
    Returns HTTPS settings for the given host.
    - Is requests to HTTP is allowed
    - Is it HTTPS redirect.
    - Is HTTPS allowed.
    """

    http_is_allowed, https_is_allowed, has_https_enforcment = True, True, False

    http_request = safe_make_request(
        http_method="GET", http_host=http_host, is_https=False
    )

    if not http_request:
        http_is_allowed = False

    if http_request.is_redirect or http_request.is_permanent_redirect:
        has_https_enforcment = True

    https_request = safe_make_request(
        http_method="GET", http_host=http_host, is_https=True
    )

    if not https_request:
        https_is_allowed = False

    return http_is_allowed, has_https_enforcment, https_is_allowed


# Be sure.
inject_custom_make_request()

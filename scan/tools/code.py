"""
    Tools for working with code analysis etc.
"""

from string import digits, ascii_letters

from .triggers import (
    CODE_SOURCE_FRAMEWORKS_TRIGGERS,
    CODE_INCLUDE_PATH_FRAMEWORKS_TRIGGERS,
)
from .http import safe_make_request


def get_js_scripts_from_html(
    html: str, exclude_external_sources: bool = False
) -> list[str]:
    """
    Returns JavaScript scripts urls that is used in that HTML.
    Use `exclude_external_sources` to exclude external includes.

    """
    scripts_urls = []
    while True:
        # Find open tag.
        loc = html.find("<script")
        if loc == -1:
            break

        # Find source path.
        html = html[loc:]
        loc = html.find("src=")
        if loc == 0:
            continue
        html = html[loc + len("src=") + 1 :]
        loc = 0

        # Collect chars till the end.
        script_url = ""
        while True:
            script_url += html[loc]
            loc += 1
            if html[loc] not in ascii_letters + digits + "./-_:":
                break

        # Add if not already.
        if script_url not in scripts_urls:
            if not exclude_external_sources or not script_url.startswith("http"):
                scripts_urls.append(script_url)

        # Next script search.
        html = html[loc:]
    return scripts_urls


def get_css_styles_from_html(
    html: str, exclude_external_sources: bool = False
) -> list[str]:
    """
    Returns CSS styles urls that is used in that HTML.
    Use `exclude_external_sources` to exclude external includes.
    """

    styles_urls = []
    while True:
        # Find open tag.
        loc = html.find("<link")
        if loc == -1:
            break

        # Find source path.
        html = html[loc + 1 :]
        loc = html.find("href=")
        if loc == 0:
            continue
        if html.find("stylesheet") == -1 or html.find("stylesheet") > html.find(">"):
            continue
        html = html[loc + len("href=") + 1 :]
        loc = 0

        # Collect chars till the end.
        style_url = ""
        while True:
            style_url += html[loc]
            loc += 1
            if html[loc] not in ascii_letters + digits + "./-_:":
                break

        # Add if not already.
        if style_url not in styles_urls:
            if not exclude_external_sources or not style_url.startswith("http"):
                styles_urls.append(style_url)

        # Next style search.
        html = html[loc:]
    return styles_urls


def get_frameworks_from_html(html_payload: str, http_host: str) -> list[str]:
    """
    Returns list of frameworks and like that from HTML payload.
    """
    frameworks = []

    # Load HTML.
    includes = get_js_scripts_from_html(
        html_payload, exclude_external_sources=True
    ) + get_css_styles_from_html(html_payload, exclude_external_sources=False)

    for include_url in includes:
        # Non-external url.
        if not include_url.startswith("http"):
            include_url = f"{http_host}{('/' if not include_url.startswith('/') else '')}{include_url}"

        # Check for include path.
        for trigger, name in CODE_INCLUDE_PATH_FRAMEWORKS_TRIGGERS.items():
            if trigger in include_url and name not in frameworks:
                frameworks.append(name)

        # Load file.
        request = safe_make_request(
            http_method="GET",
            http_host=include_url,
            is_https=False,
        )
        if not request:
            continue

        # Scan payload for file.
        for trigger, name in CODE_SOURCE_FRAMEWORKS_TRIGGERS.items():
            if trigger in request.text and name not in frameworks:
                frameworks.append(name)
    return frameworks


def get_api_locations_from_html(
    html_payload: str, http_host: str, _already_scanned_paths: list | None = None
) -> list[str]:
    """
    Returns API locations that is used inside overall HTML includes and stuff.
    """
    _already_scanned_paths = _already_scanned_paths if _already_scanned_paths else []

    api_locations = []
    while True:
        # Find API keywords.
        loc = html_payload.find("api")
        if loc == -1:
            break
        api_location = ""
        while True:
            api_location += html_payload[loc]
            loc += 1
            if html_payload[loc] not in ascii_letters + ".":
                break

        # If not already found or it is current host.
        if (
            api_location not in api_locations
            and "." in api_location
            and http_host.lower() in api_location.lower()
        ):
            api_locations.append(api_location)

        # Next API search.
        html_payload = html_payload[loc:]

    for js_script_path in get_js_scripts_from_html(
        html_payload, exclude_external_sources=True
    ):
        # Scan JavaScript sources.

        # Do not repeat scan.
        if js_script_path in _already_scanned_paths:
            continue
        _already_scanned_paths.append(js_script_path)

        if not js_script_path.startswith("http"):
            js_script_path = f"{http_host}{('/' if not js_script_path.startswith('/') else '')}{js_script_path}"

        request = safe_make_request(
            http_method="GET",
            http_host=js_script_path,
            is_https=False,
        )
        if not request:
            print(
                f":WARNING: Unable to load `{js_script_path}` when getting API locations!"
            )
            continue
        api_locations.extend(
            get_api_locations_from_html(
                html_payload=request.text,
                http_host=js_script_path,
                _already_scanned_paths=_already_scanned_paths,
            )
        )
    return list(set(api_locations))

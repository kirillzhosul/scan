import datetime
import socket
import sys
import threading
import time

import requests
import whois
from github import Github
from requests.packages.urllib3.connectionpool import HTTPConnectionPool

TAB = "\t"

REQ_COUNT = 0


def TCP_connect(ip, port, delay, ports):
    TCPsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    TCPsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    TCPsock.settimeout(delay)
    try:
        TCPsock.connect((ip, port))
        ports.append(port)
    except:
        pass


def scan_ports(host_ip) -> list:
    threads = []
    ports = []

    port_range = range(10000)
    for i in port_range:
        t = threading.Thread(target=TCP_connect, args=(host_ip, i, 1, ports))
        threads.append(t)

    for i in port_range:
        threads[i].start()

    for i in port_range:
        threads[i].join()

    return ports


def _make_request(self, conn, method, url, **kwargs):
    response = self._old_make_request(conn, method, url, **kwargs)
    sock = getattr(conn, "sock", False)
    if sock:
        setattr(response, "peer", sock.getpeername())
    else:
        setattr(response, "peer", (None, None))
    return response


HTTPConnectionPool._old_make_request = HTTPConnectionPool._make_request
HTTPConnectionPool._make_request = _make_request


def make_request(method: str, url: str, https: bool):
    url = f"{('https://' if https else 'http://') if not url.startswith('http') else ''}{url}"
    return requests.request(
        method=method,
        url=url,
        headers={"User-Agent": ""},
    )


def parse_argv():
    _, *argv = sys.argv

    if len(argv) == 0:
        print("Please specify command!")
        exit(1)
    command, *argv = argv

    if len(argv) == 0:
        print("Please specify URL/IP of the target!")
        exit(1)
    target, *flags = argv

    return command, target, flags


def _scan_http_methods(target):
    methods_to_scan = [
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
    allowed_methods = []
    for method in methods_to_scan:
        try:
            req = make_request(method=method, url=target, https=False)
            if req.status_code == 200:
                allowed_methods.append(method)
        except requests.ConnectionError:
            pass
    return allowed_methods


def _scan_ssl(target):
    insecure_http_allowed, https_allowed, https_redirect = False, False, False
    try:
        req = make_request(method="GET", url=target, https=False)
        insecure_http_allowed = True
        if not req.status_code >= 300 and req.status_code < 400:
            https_redirect = True
            insecure_http_allowed = False

    except requests.ConnectionError:
        pass

    try:
        req = make_request(method="GET", url=target, https=True)
        https_allowed = True
    except requests.ConnectionError:
        pass
    return insecure_http_allowed, https_allowed, https_redirect


def bool_format(_bool: bool):
    return "yes" if _bool else "no"


def _scan_web_trackers(req: requests.Response):
    trackers_payloads = {
        "mc.yandex.ru": "Yandex Metrika",
        "m,e,t,r,i,k,a": "Yandex Metrika",
    }
    found_trackers = []
    for tracker_payload, tracker_name in trackers_payloads.items():
        if tracker_payload in req.text and tracker_name not in found_trackers:
            found_trackers.append(tracker_name)
    return found_trackers


def _get_included_javascript_locations(
    req: requests.Response, exclude_external: bool = False
):
    included_javascript = []
    body = req.text
    while True:
        loc = body.find("<script")
        if loc == -1:
            break
        body = body[loc:]
        loc = body.find("src=")
        if loc == 0:
            continue
        body = body[loc + len("src=") + 1 :]
        loc = 0
        javascript_url = ""

        while True:
            javascript_url += body[loc]
            loc += 1
            if body[loc] not in "qwertyuiopasdfghjklzxcvbnm./-_1234567890:":
                break
        if javascript_url not in included_javascript:
            if not exclude_external:
                included_javascript.append(javascript_url)
            else:
                if not javascript_url.startswith("http"):
                    included_javascript.append(javascript_url)
        body = body[loc:]
    return included_javascript


def _get_included_css_locations(req: requests.Response, exclude_external: bool = False):
    included_css = []
    body = req.text
    while True:
        loc = body.find("<link")
        if loc == -1:
            break
        body = body[loc + 1 :]
        loc = body.find("href=")
        if loc == 0:
            continue
        if body.find("stylesheet") == -1 or body.find("stylesheet") > body.find(">"):
            continue

        body = body[loc + len("href=") + 1 :]
        loc = 0
        css_url = ""
        while True:
            css_url += body[loc]
            loc += 1
            if body[loc] not in "qwertyuiopasdfghjklzxcvbnm./-_1234567890:":
                break
        if css_url not in included_css:
            if not exclude_external:
                included_css.append(css_url)
            else:
                if not css_url.startswith("http"):
                    included_css.append(css_url)
        body = body[loc:]
    return included_css


def _scan_possible_api_locations(
    req: requests.Response, target: str, _already_scanned_js: list | None = None
):
    if _already_scanned_js is None:
        _already_scanned_js = []
    possible_api_locations = []
    body = req.text
    while True:
        loc = body.find("api")
        if loc == -1:
            break
        api_location = ""
        while True:
            api_location += body[loc]
            loc += 1
            if body[loc] not in "qwertyuiopasdfghjklzxcvbnm.":
                break
        if (
            api_location not in possible_api_locations
            and "." in api_location
            and target.lower() in api_location.lower()
        ):
            possible_api_locations.append(api_location)
        body = body[loc:]
    included_js = _get_included_javascript_locations(req, exclude_external=True)

    for js_include in included_js:
        if js_include in _already_scanned_js:
            continue
        if js_include not in _already_scanned_js:
            _already_scanned_js.append(js_include)
        possible_api_locations.extend(
            _scan_possible_api_locations(
                make_request(
                    method="GET",
                    url=target
                    + ("/" if not js_include.startswith("/") else "")
                    + js_include,
                    https=True,
                ),
                target=target,
                _already_scanned_js=_already_scanned_js,
            )
        )
    return list(set(possible_api_locations))


def _scan_possible_frameworks(req: requests.Response, target: str):
    CSS_FRAMEWORKS = {
        "--chakra": "Chakra UI",
        "--vkui": "VK UI",
        "bootstrap": "Bootstrap",
    }
    possible_frameworks = []
    included_js = _get_included_javascript_locations(req, exclude_external=True)
    for js_script in included_js:
        if js_script.startswith("/_next") and "Next.js" not in possible_frameworks:
            possible_frameworks.append("Next.js")
    included_css = _get_included_css_locations(req, exclude_external=False)
    for include_url in included_css + included_js:
        if not include_url.startswith("http"):
            include_url = (
                target + ("/" if not include_url.startswith("/") else "") + include_url
            )
        css_req = make_request(
            method="GET",
            url=include_url,
            https=True,
        )
        for css_payload, css_framework in CSS_FRAMEWORKS.items():
            if css_payload in css_req.text and css_framework not in possible_frameworks:
                possible_frameworks.append(css_framework)
    return possible_frameworks


def command_info(target, flags):
    t = time.time()
    _req = None
    try:
        _req = make_request(method="GET", url=target, https=False)
    except requests.ConnectionError:
        pass

    host_is_reachable = _req is not None

    if not host_is_reachable:
        print("Actually, host is unreachable!")
        exit(1)
    print(" ... Scanning HTTP methods ... ")
    allowed_methods = _scan_http_methods(target) if host_is_reachable else []

    print(" ... Scanning web trackers ... ")
    trackers_installed = _scan_web_trackers(_req)

    print(" ... Scanning HTTPS / SSL ... ")
    insecure_http_allowed, https_allowed, https_redirect = (
        _scan_ssl(target) if host_is_reachable else (False, False)
    )
    host_ip, host_port = _req.raw._original_response.peer[:2]
    server = _req.headers.get("server", None)
    x_server = _req.headers.get("x-powered-by", None)

    print(" ... Scanning whois ... ")

    w = whois.whois(url=target)

    print(" ... Scanning possible API locations ... ")
    possible_api_locations = _scan_possible_api_locations(_req, target)

    print(" ... Scanning possible frameworks ... ")
    possible_frameworks = _scan_possible_frameworks(_req, target)

    print(" ... Searching GitHub references ...")
    github_references = "\n".join(
        [
            "\t\t - https://github.com/"
            + ghr.full_name
            + f" ({ghr.stargazers_count} stars)"
            for ghr in Github().search_repositories(
                query=target, sort="stars", order="desc"
            )[:3]
        ]
    )

    if "-skip-ports" in flags:
        ports = []
    else:
        print(" ... Scanning ports ... ")
        ports = scan_ports(host_ip)

    domain_expires_at = (
        w.expiration_date
        if not isinstance(w.expiration_date, list)
        else max(w.expiration_date)
    )
    problems = []
    if https_allowed and not https_redirect:
        problems.append("No HTTP->HTTPS (SSL) enforcement (Redirect)")
    if 21 in ports or 20 in ports:
        problems.append("FTP opened at the default port!")
    if 22 in ports:
        problems.append("SSH opened at the default port!")
    if 8080 in ports:
        problems.append("Alternate HTTP port opened (:8080)!")
    problems_count = len(problems)
    problems = "".join([f"\t\t- {problem}" + "\n" for problem in problems])
    print(
        f"""
Finished scanning target (=`{target}`) with results (taked {time.time() - t}s):
\tFinal URL: {_req.url}

\tHost:
\t\tIP: {host_ip} (:{host_port})
\t\tIs reachable: {bool_format(host_is_reachable)}
\t\tServer: {server or 'Hidden, or not specified'}{f' (X-Server: {x_server})' if x_server else ''}
\t\tPorts opened: {', '.join(map(str, ports[:15]))} {'(first 15)' if len(ports) > 15 else ''} ({len(ports)} total)

\tHTTP(s):
\t\tHTTPS allowed: {bool_format( https_allowed)}
\t\tInsecure HTTP allowed: {bool_format(insecure_http_allowed)} (HTTPS redirect: {bool_format(https_redirect)})
\t\tAllowed HTTP methods: {', '.join(allowed_methods)}

\tDomain (`{w.domain_name}`):
\t\tRegistered (Created) at: {w.creation_date} (For {((domain_expires_at - w.creation_date).days) if domain_expires_at else '0'} days)
\t\tExpires at: {domain_expires_at} (Will expire in {((domain_expires_at - datetime.datetime.now()).days) if domain_expires_at else '0'} days)
\t\tWas updated at: {w.updated_at or 'Never'}

\tWeb:
\t\tResponse content type: {_req.headers.get('content-type', 'Hidden, or not specified (?)')}
\t\tHas explicit cookies setters: {bool_format('set-cookie' in _req.headers)}
\t\tHas web trackers: {', '.join(trackers_installed) if trackers_installed else 'Not found'}
\t\tPossible API locations: {', '.join(possible_api_locations) if possible_api_locations else 'Not detected'}
\t\tPossible frameworks: {', '.join(possible_frameworks) if possible_frameworks else 'Not detected'}

\tOther:
\t\tTop 3 popular references in GitHub: \n{github_references}
\tTotal problems ({problems_count}):
{problems if problems_count != 0 else f'{TAB}{TAB}No problems found!'}
"""
    )


def _preprocess_target(target: str):
    if target.startswith("https://"):
        target = target[len("https://") :]
    if target.startswith("http://"):
        target = target[len("http://") :]

    return target.replace("/", "")


def execute_command(command, target, flags):
    target = _preprocess_target(target)
    if command == "info":
        command_info(target, flags)
        return
    print(f"Unknown command {command}!")
    exit(1)


def main():
    execute_command(*parse_argv())


if __name__ == "__main__":
    main()

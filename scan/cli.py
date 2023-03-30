"""
    CLI interface of the scanner.
"""

from sys import argv
from enum import auto, Enum
from dataclasses import dataclass

from tools.utils import preprocess_target
from tools.injected_make_request import get_peer_from_request


class CLIFlag(Enum):
    """
    Flags from CLI.
    """

    skip_ports_scanning = auto()
    skip_whois_scanning = auto()
    skip_code_scanning = auto()
    skip_github_scanning = auto()
    skip_http_scanning = auto()
    skip_all = auto()


@dataclass
class CLIArgs:
    """
    Arguments from runner CLI.
    """

    app_path: str
    cli_command: str
    cli_flags: list[str]
    targets: list[str]


def usage() -> None:
    """
    Prints usage message.
    """

    app_path = argv[0]
    print(
        f"""
Usage: {app_path} <command> <target(s)> [flags]

Commands:
    - <scan>: Makes full scan of the target(s).
    - <help>: Prints this message.
"""
    )
    exit(1)


def parse_argv() -> CLIArgs:
    """
    Parses and converts ARG(V) into CLI args dataclass.
    """
    app_path, *args = argv

    if len(args) == 0:
        print(":ERROR: Please specify command!")
        usage()
    cli_command, *args = args

    if len(args) == 0:
        print(":ERROR: Please specify target(s)! (Actually, domain or IP)")
        usage()

    # Take targets from CLI.
    targets = []
    for arg in args:
        if arg.startswith("-"):
            break
        target, *args = args
        targets.append(target)

    cli_flags = []
    for flag in args:
        if flag not in CLI_FLAGS:
            print(":ERROR: Unknown flag `{flag}`!")
            usage()
        cli_flags.append(CLI_FLAGS[flag])
    return CLIArgs(
        app_path=app_path, cli_command=cli_command, cli_flags=cli_flags, targets=targets
    )


def execute_command(cli_args: CLIArgs) -> None:
    """
    Executes command.
    """
    return CLI_COMMANDS[cli_args.cli_command](
        targets=cli_args.targets, cli_flags=cli_args.cli_flags
    )


def cli_main() -> None:
    """
    Entry point.
    """
    cli_args = parse_argv()
    cli_args.targets = [preprocess_target(target) for target in cli_args.targets]
    if cli_args.cli_command in CLI_COMMANDS:
        execute_command(cli_args=cli_args)
    else:
        print(f":ERROR: Unknown command {cli_args.cli_command}!")
        usage()


CLI_FLAGS = {
    # Ports.
    "-skip-ports-scanning": CLIFlag.skip_ports_scanning,
    "-skip-ports": CLIFlag.skip_ports_scanning,
    "-sp": CLIFlag.skip_ports_scanning,
    # Whois.
    "-skip-whois-scanning": CLIFlag.skip_whois_scanning,
    "-skip-whois": CLIFlag.skip_whois_scanning,
    "-sw": CLIFlag.skip_whois_scanning,
    # Code.
    "-skip-code-scanning": CLIFlag.skip_code_scanning,
    "-skip-code": CLIFlag.skip_code_scanning,
    "-sc": CLIFlag.skip_code_scanning,
    # Github.
    "-skip-github-scanning": CLIFlag.skip_github_scanning,
    "-skip-github": CLIFlag.skip_github_scanning,
    "-sg": CLIFlag.skip_github_scanning,
    # HTTP.
    "-skip-http-scanning": CLIFlag.skip_http_scanning,
    "-skip-http": CLIFlag.skip_http_scanning,
    "-sh": CLIFlag.skip_http_scanning,
    # All.
    "-skip-all-scanning": CLIFlag.skip_all,
    "-skip-all": CLIFlag.skip_all,
    "-sa": CLIFlag.skip_all,
}


import time
import datetime

import whois
from tools.utils import format_bool
from tools.trackers import get_web_trackers
from tools.ports import get_available_ports
from tools.http import safe_make_request, get_https_settings, get_allowed_http_methods
from tools.github import get_top_repos_by_query
from tools.code import get_frameworks_from_html, get_api_locations_from_html


def cli_command_info(targets, cli_flags):
    # Workaround till there is no support for multiple targets yet.
    target = targets[0]

    # Track when we are started scan.
    start_time = time.time()

    # First request to start scan! :)
    initial_request = safe_make_request(
        http_method="GET", http_host=target, is_https=False
    )
    if not initial_request:
        print(":ERROR: Actually given target is unreachable!")
        exit(1)
    initial_html = initial_request.text
    host_ip, host_port = get_peer_from_request(initial_request)

    print("... Checking for allowed HTTP methods ... ")
    allowed_http_methods = get_allowed_http_methods(http_host=target)

    print("... Checking for web trackers installed ... ")
    web_trackers = get_web_trackers(initial_html)

    print("... Checking HTTPS / SSL settings ... ")
    http_is_allowed, https_is_allowed, has_https_enforcment = get_https_settings(target)

    print("... Checking domain information (Whois) ... ")
    w = whois.whois(url=target)
    domain_expires_at = (
        w.expiration_date
        if not isinstance(w.expiration_date, list)
        else max(w.expiration_date)
    )

    print("... Checking API locations in the code ... ")
    api_locations = get_api_locations_from_html(initial_html, target)

    print("... Checking frameworks ... ")
    frameworks = get_frameworks_from_html(initial_html, target)

    print("... Checking top GitHub references ...")
    github_references = "\n".join(
        f"\t\t - {repo[0]} ({repo[1]} stars)" for repo in get_top_repos_by_query(target)
    )

    print("... Checking opened ports ... ")
    available_ports = get_available_ports(host_ip)

    server = initial_request.headers.get("server", "Hidden, or not specified")
    x_server = initial_request.headers.get("x-powered-by", None)

    print(
        f"""
Finished scanning target (=`{target}`) with results (taked {int(time.time() - start_time)}s):
\tFinal URL: {initial_request.url}

\tHost:
\t\tIP: {host_ip} (Port: {host_port})
\t\tServer header: {server}{f' (X-Server header: {x_server})' if x_server else ''}
\t\tPorts opened: {', '.join(map(str, available_ports[:15]))} {'(first 15)' if len(available_ports) > 15 else ''} ({len(available_ports)} total)

\tHTTP(s):
\t\tInsecure HTTP allowed: {format_bool(http_is_allowed)} 
\t\tHTTPS allowed: {format_bool(https_is_allowed)}
\t\tHTTP->HTTPS redirect: {format_bool(has_https_enforcment)})
\t\tAllowed HTTP methods: {', '.join(allowed_http_methods)}

\tDomain (`{w.domain_name}`):
\t\tRegistered (Created) at: {w.creation_date} (For {((domain_expires_at - w.creation_date).days) if domain_expires_at else '0'} days)
\t\tExpires at: {domain_expires_at} (Will expire in {((domain_expires_at - datetime.datetime.now()).days) if domain_expires_at else '0'} days)
\t\tWas updated at: {w.updated_at or 'Never'}

\tWeb:
\t\tResponse content type: {initial_request.headers.get('content-type', 'Hidden, or not specified (?)')}
\t\tHas explicit cookies setters: {format_bool('set-cookie' in initial_request.headers)}
\t\tHas web trackers: {', '.join(web_trackers) if web_trackers else 'Not found'}
\t\tPossible API locations: {', '.join(api_locations) if api_locations else 'Not found'}
\t\tPossible frameworks: {', '.join(frameworks) if frameworks else 'Not found'}

\tOther:
\t\tTop 3 popular references in GitHub: \n{github_references}
"""
    )


CLI_COMMANDS = {"info": cli_command_info, "help": usage}

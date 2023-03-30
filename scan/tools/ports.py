"""
    Utility to check available ports on the target socket.
"""
import threading
import socket


def get_available_ports(target_socket_ip: str) -> list[int]:
    """
    Returns list of available ports on the target socket IP.
    """

    threads = []
    ports_ref = []

    for port in SCAN_PORTS_RANGE:
        t = threading.Thread(
            target=_port_check_socket_tcp_connect,
            args=(target_socket_ip, port, ports_ref),
        )
        threads.append(t)

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    return ports_ref


def _port_check_socket_tcp_connect(
    socket_ip: str, socket_port: int, ports_ref: list[int], timeout: int = 1
):
    """
    Creates default TCP socket to check if port is available.
    """
    # Default TCP socket.
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_socket.settimeout(timeout)

    # Tries to connect or just leave away.
    try:
        tcp_socket.connect((socket_ip, socket_port))
    except Exception:
        return

    # Port is available.
    ports_ref.append(socket_port)


SCAN_PORTS_LIMIT = 10_000
SCAN_PORTS_RANGE = range(SCAN_PORTS_LIMIT)

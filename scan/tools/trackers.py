"""
    Stuff for scanning web trackers inside body.
"""
from .triggers import WEB_TRACKERS_TRIGGERS


def get_web_trackers(payload: str) -> list[str]:
    """
    Returns web tracker names from payload (Actually HTML / text).
    """
    return list(
        {name for trigger, name in WEB_TRACKERS_TRIGGERS.items() if trigger in payload}
    )

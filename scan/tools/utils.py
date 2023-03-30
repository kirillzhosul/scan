"""
    Some utils.
"""


def format_bool(value: bool) -> str:
    """
    Just returns yes or no instead of True / False.
    """
    return "yes" if value else "no"


def preprocess_target(target: str) -> str:
    """
    Makes all required convertions for target.
    """

    # Removes HTTP/S prefixes.
    if target.startswith("https://"):
        target = target[len("https://") :]
    if target.startswith("http://"):
        target = target[len("http://") :]

    # You are unable to use locations in targets.
    return target.replace("/", "")

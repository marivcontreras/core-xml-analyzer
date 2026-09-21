# Centralized warning catalog loader.
# The catalog itself lives in resources/warnings.yaml (message, type, scope,
# subject, requires_ipv6). This module loads it and exposes accessors.

import os
import yaml

_CATALOG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "resources", "warnings.yaml"
)


def _load_catalog(path=_CATALOG_PATH):
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data or {}


WARNINGS = _load_catalog()


def get_warning(code):
    """
    Retrieve a warning template by code.

    Args:
        code: Warning code key

    Returns:
        Warning template dict or None if code not found
    """
    return WARNINGS.get(code)

def get_warning_message(code, **kwargs):
    """
    Retrieve and format a warning message by code.

    Args:
        code: Warning code key
        **kwargs: Format parameters for the message template

    Returns:
        Formatted message string or None if code not found
    """
    if code not in WARNINGS:
        return None

    template = WARNINGS[code].get("message", "")
    try:
        return template.format(**kwargs)
    except KeyError as e:
        # Return template with unfilled placeholders if kwargs are incomplete
        return template

def get_warning_type(code):
    """Get the type of a warning by code."""
    return WARNINGS.get(code, {}).get("type", "generic")

def get_warning_scope(code):
    """Get the scope of a warning by code."""
    return WARNINGS.get(code, {}).get("scope", "network")

def get_warning_subject(code):
    """Get the subject (report section / course topic) of a warning by code."""
    return WARNINGS.get(code, {}).get("subject")

def get_warning_requires_ipv6(code):
    """True if the warning only applies to IPv6-capable classes."""
    return bool(WARNINGS.get(code, {}).get("requires_ipv6", False))

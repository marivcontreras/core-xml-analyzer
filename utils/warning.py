from validation.warnings import (
    get_warning_message, get_warning_type, get_warning_scope,
    get_warning_subject, get_warning_requires_ipv6,
)
from utils import config_helper
from utils.subjects import Subject
from utils.routing_config import TABLES


def _should_emit(code):
    """Decide whether a warning code applies to the current class.

    A warning is suppressed when its subject is not among the class's active
    subjects, or when it requires IPv6 and the class has no IPv6 support.
    Warnings with no subject declared are always emitted (fail-open).
    """
    subject = get_warning_subject(code)
    if subject is not None:
        try:
            active = config_helper.get_subjects()
        except ValueError:
            active = None
        if active is not None and Subject.from_value(subject) not in active:
            return False

    if get_warning_requires_ipv6(code):
        try:
            if not config_helper.get_ipv6_support():
                return False
        except ValueError:
            pass

    return True


def add_warning(data, code, *, wtype=None, scope=None,
                network=None, node=None, interface=None,
                details=None, **format_kwargs):
    """
    Add a warning to the data using a warning code and format parameters.

    Args:
        data: The data dictionary containing warnings list
        code: Warning code key from resources.warnings
        wtype: Override warning type (optional, uses resource default)
        scope: Override warning scope (optional, uses resource default)
        network, node, interface: Context metadata
        details: Additional details dictionary
        **format_kwargs: Format parameters for message template
    """
    if not _should_emit(code):
        return

    message = get_warning_message(code, **format_kwargs)
    if not message:
        raise ValueError(f"Unknown warning code: {code}")

    warning = {
        "message": message,
        "type": wtype or get_warning_type(code),
        "scope": scope or get_warning_scope(code),
        "code": code,
    }

    if network:
        warning["network"] = network
    if node:
        warning["node"] = node
    if interface:
        warning["interface"] = interface
    if details:
        warning["details"] = details

    data["warnings"].append(warning)


def add_routing_warning(routing, category, code, warnings_list=None, router=None, route=None, route_id=None, **format_kwargs):
    """
    Add a routing warning using a warning code and format parameters.

    Args:
        routing: The routing dictionary containing warnings, or None if warnings_list provided
        category: Warning category (routing, isp, tunnels, etc.)
        code: Warning code key from resources.warnings
        warnings_list: Optional list to append warning to (for routing matrix validation)
        route_id: Optional route identifier to attach to the warning
        **format_kwargs: Format parameters for message template
    """
    if not _should_emit(code):
        return

    warning = {
        "router": format_kwargs.get("router_name", router),
        "route": format_kwargs.get("route_name", route),
        "prefix_type": format_kwargs.get("prefix_type") or None,
        "route_id": route_id,
        "severity": get_warning_type(code),
        "code": code,
        "table": format_kwargs.get("table") or "main"
    }  

    if format_kwargs.get("table"):
        format_kwargs["table"] = TABLES.get(format_kwargs["table"], format_kwargs["table"])

    # `route` is consumed above as an explicit parameter (to populate
    # warning["route"] when the caller doesn't pass route_name), so it
    # never reaches **format_kwargs on its own. Some message templates
    # (e.g. invalid_default_route) use a {route} placeholder, so make
    # sure that value is still available for formatting.
    format_kwargs.setdefault("route", route)

    message = get_warning_message(code, **format_kwargs)
    if not message:
        raise ValueError(f"Unknown warning code: {code}")
    warning["message"] = message    

    if warnings_list is not None:
        warnings_list.append(warning)
    else:
        routing["warnings"][category].append(warning)

def replicate_routing_warning(routing, category, warning):

    routing["warnings"][category].append(
        warning
    )
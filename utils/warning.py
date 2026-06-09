from resources.warnings import get_warning_message, get_warning_type, get_warning_scope
from validation.routingHelper import TABLES

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
    #print(f"Format kwargs: {format_kwargs}")
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
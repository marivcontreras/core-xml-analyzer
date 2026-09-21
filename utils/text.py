"""Generic string/formatting helpers shared across layers.

These are pure text utilities with no dependency on the report layer, so they
live in utils and can be imported by parser/analyzer/validation without
inverting the layering (parse -> analyze -> validate -> report).
"""

from utils import config_helper


def strip_comments(text):
    lines = text.splitlines()
    cleaned = []

    for line in lines:
        line = line.strip()

        # ignorar línea completa comentada
        if line.startswith("#"):
            continue

        # eliminar comentario inline
        if "#" in line:
            line = line.split("#", 1)[0].strip()

        if line:
            cleaned.append(line)

    return "\n".join(cleaned)


# -------------------------------------------------
# Composes via information into a readable string
# -------------------------------------------------
def format_via_info(via_info):
    if not via_info:
        return "-"

    if isinstance(via_info, dict):
        via_info = [via_info]

    formatted = []

    for item in via_info:

        node = item.get("node", "?")
        interface = item.get("interface", "?")
        network = item.get("network")

        if (node is None and interface is None and network is None):
            return "La dirección no existe en la topología"

        text = f"{node}-{interface}"

        if network:
            text += f" en red {config_helper.format_network_name(network)}"

        formatted.append(text)

    return " | ".join(formatted)


# -------------------------------------------------
# Composes route information into a readable string
# -------------------------------------------------
def format_route(route):
    if not route:
        return "-"

    parts = []
    id = route.get("related_id")
    route_type = route.get("type")
    dst = route.get("dst")
    table = route.get("table")
    dev = route.get("dev")
    via_info = route.get("via_info")

    if id:
        parts.append(f"id={id}")

    if route_type:
        parts.append(f"type={route_type}")

    if dst:
        parts.append(f"dst={dst}")

    if via_info:
            parts.append(
                f"via={format_via_info(via_info)}"
            )

    if dev:
        parts.append(f"dev={dev}")

    if table:
        parts.append(f"table={table}")

    if route.get("is_policy"):
        parts.append("policy")

    return " | ".join(parts)


# -------------------------------------------------
# Reverses P2P network name if it contains "<>", e.g. "R1<>R2" -> "R2<>R1"
# -------------------------------------------------
def reverse_network_name(route_name):
    if "<>" in route_name:
        parts = [p.strip() for p in route_name.split("<>")]
        if len(parts) == 2:
            return f"{parts[1]}<>{parts[0]}"
    return route_name

import ipaddress
import re

from utils.warning import add_warning
from validation.command_lines import extract_commands, tokenize_command
from validation.configs.route_config import (
    ROUTE_DEFINING_ACTIONS, ROUTE_OTHER_ACTIONS, ROUTE_TYPES,
    ROUTE_TYPES_WITHOUT_NEXT_HOP, DEFAULT_DESTINATIONS, ROUTE_KEYWORDS,
    ROUTE_UNIQUE_KEYWORDS, ROUTE_INT_MAX,
)

ROUTE_COMMAND_REGEX = r"ip(?:\s+-[46])?\s+route\b"

# -------------------------------------------------------------
# Validates the syntax of every "ip route" command found in the StaticRoute
# script of a node. One warning is emitted per invalid command, listing every
# problem found in it.
# -------------------------------------------------------------
def validate_route_commands(node_id, data):
    text = data["services"].get(node_id, {}).get("StaticRoute", "")
    node_name = data["devices"].get(node_id, {"name": f"node{node_id}"})["name"]

    for line_num, line in extract_commands(text, ROUTE_COMMAND_REGEX):
        errors = check_route_command(line)

        if errors:
            add_warning(
                data,
                "invalid_route_command",
                node=node_name,
                node_name=node_name,
                line=line,
                errors="; ".join(errors),
                details={"line": line, "line_number": line_num}
            )

# -------------------------------------------------------------
# Returns the list of syntax problems of a single command (empty if valid).
# -------------------------------------------------------------
def check_route_command(line):
    try:
        tokens = tokenize_command(line)
    except ValueError:
        return ["comillas sin cerrar"]

    # ip [-4|-6] route <action> [type] <destination> [keyword value ...]
    tokens = tokens[1:]
    version = None

    if tokens and tokens[0] in ("-4", "-6"):
        version = int(tokens[0][1])
        tokens = tokens[1:]

    tokens = tokens[1:]  # "route"

    if not tokens:
        return ["falta la acción (add, del, ...)"]

    action = tokens[0]
    tokens = tokens[1:]

    if action in ROUTE_OTHER_ACTIONS:
        return []

    if action not in ROUTE_DEFINING_ACTIONS:
        return [f"acción desconocida '{action}'"]

    errors = []
    route_type = "unicast"

    if tokens and tokens[0] in ROUTE_TYPES:
        route_type = tokens[0]
        tokens = tokens[1:]

    # ---------------------------------------------
    # destination
    # ---------------------------------------------
    if not tokens or tokens[0] in ROUTE_KEYWORDS:
        errors.append("falta el destino")
        destination = None
    else:
        destination = tokens[0]
        tokens = tokens[1:]
        version, problem = check_destination(destination, version)
        if problem:
            errors.append(problem)

    # ---------------------------------------------
    # keyword / value pairs
    # ---------------------------------------------
    seen = {}
    i = 0
    while i < len(tokens):
        keyword = tokens[i]
        i += 1

        if keyword not in ROUTE_KEYWORDS:
            errors.append(f"opción desconocida '{keyword}'")
            continue

        kind = ROUTE_KEYWORDS[keyword]

        if keyword in ROUTE_UNIQUE_KEYWORDS and keyword in seen:
            errors.append(f"'{keyword}' está repetido")

        if kind is None:
            seen[keyword] = True
            continue

        # "via inet6 <addr>" is the long form of the next hop family
        if keyword == "via" and i < len(tokens) and tokens[i] in ("inet", "inet6"):
            i += 1

        if i >= len(tokens) or tokens[i] in ROUTE_KEYWORDS:
            errors.append(f"falta el valor de '{keyword}'")
            continue

        value = tokens[i]
        i += 1
        seen[keyword] = value

        problem = check_keyword_value(keyword, kind, value, version)
        if problem:
            errors.append(problem)

    # ---------------------------------------------
    # coherence between fields
    # ---------------------------------------------
    if destination is not None and route_type not in ROUTE_TYPES_WITHOUT_NEXT_HOP:
        if "via" not in seen and "dev" not in seen:
            errors.append("falta via o dev")

    return errors

# -------------------------------------------------------------
# Destination: default, or a network whose host bits are zero.
# Returns (ip version or None, problem or None).
# -------------------------------------------------------------
def check_destination(destination, version):
    if destination == "default":
        return version, None

    try:
        network = ipaddress.ip_network(destination, strict=True)
    except ValueError as e:
        try:
            ipaddress.ip_network(destination, strict=False)
            return version, f"destino '{destination}' con bits de host en 1 (prefijo inválido para la máscara)"
        except ValueError:
            return version, f"destino inválido '{destination}'"

    if version is not None and network.version != version:
        return version, f"destino IPv{network.version} '{destination}' en un comando ip -{version} route"

    return network.version, None

def check_keyword_value(keyword, kind, value, version):
    if kind == "addr":
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return f"dirección inválida '{value}' en {keyword}"

        if version is not None and address.version != version:
            return f"dirección IPv{address.version} '{value}' en {keyword} de una ruta IPv{version}"

    elif kind == "iface":
        if not re.fullmatch(r"[a-zA-Z0-9_.:@-]+", value):
            return f"interfaz inválida '{value}'"

    elif kind == "table":
        if value.isdigit():
            if int(value) > ROUTE_INT_MAX:
                return f"número de tabla fuera de rango '{value}'"
        elif not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]*", value):
            return f"nombre de tabla inválido '{value}'"

    elif kind == "int":
        if not value.isdigit() or int(value) > ROUTE_INT_MAX:
            return f"valor inválido '{value}' en {keyword}"

    return None

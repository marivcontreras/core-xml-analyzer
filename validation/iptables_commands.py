import ipaddress
import re

from utils.warning import add_warning
from validation.command_lines import extract_commands, tokenize_command
from validation.configs.iptables_config import (
    IPTABLES_BINARIES, IPTABLES_TABLES, RULE_OPERATIONS, OTHER_OPERATIONS,
    BUILTIN_TARGETS, PROTOCOLS, PORT_PROTOCOLS, OPTION_KINDS, PORT_MIN, PORT_MAX,
)

# -------------------------------------------------------------
# Validates the syntax of every iptables / ip6tables command found in the
# StaticRoute script of a node. One warning is emitted per invalid command,
# listing every problem found in it.
# -------------------------------------------------------------
def validate_iptables_commands(node_id, data):
    text = data["services"].get(node_id, {}).get("StaticRoute", "")
    node_name = data["devices"].get(node_id, {"name": f"node{node_id}"})["name"]

    commands = extract_commands(text, r"(?:%s)\b" % "|".join(IPTABLES_BINARIES))
    custom_chains = collect_custom_chains(commands)

    for line_num, line in commands:
        errors = check_iptables_command(line, custom_chains)

        if errors:
            add_warning(
                data,
                "invalid_iptables_command",
                node=node_name,
                node_name=node_name,
                line=line,
                errors="; ".join(errors),
                details={"line": line, "line_number": line_num}
            )

def collect_custom_chains(commands):
    chains = set()
    for _, line in commands:
        match = re.search(r"\s(?:-N|--new-chain)\s+(\S+)", line)
        if match:
            chains.add(match.group(1))
    return chains

# -------------------------------------------------------------
# Returns the list of syntax problems of a single command (empty if valid).
# -------------------------------------------------------------
def check_iptables_command(line, custom_chains=()):
    try:
        tokens = tokenize_command(line)
    except ValueError:
        return ["comillas sin cerrar"]

    binary = tokens[0]
    ipv6 = binary == "ip6tables"
    tokens = tokens[1:]

    if tokens and tokens[0] in ("-4", "-6"):
        ipv6 = ipv6 or tokens[0] == "-6"
        tokens = tokens[1:]

    errors = []
    operation = None
    protocol = None
    matches = set()
    port_options = []

    i = 0
    while i < len(tokens):
        token = tokens[i]

        if token == "!":
            i += 1
            if i >= len(tokens):
                errors.append("'!' sin opción")
                break
            token = tokens[i]

        # ---------------------------------------------
        # rule operations (-A, -I, -D, ...)
        # ---------------------------------------------
        if token in RULE_OPERATIONS:
            if operation is not None:
                errors.append(f"más de una operación ({operation} y {token})")
            operation = operation or token

            if i + 1 >= len(tokens) or tokens[i + 1].startswith("-"):
                errors.append(f"falta la cadena en {token}")
                i += 1
                continue

            i += 2

            # optional rule number for -I / -R
            if RULE_OPERATIONS[token] in ("insert", "replace") and i < len(tokens) and tokens[i].isdigit():
                i += 1
            continue

        if token in OTHER_OPERATIONS:
            operation = operation or token
            i += 1
            while i < len(tokens) and not tokens[i].startswith("-"):
                i += 1
            continue

        # ---------------------------------------------
        # options
        # ---------------------------------------------
        if token not in OPTION_KINDS:
            if token.startswith("-"):
                errors.append(f"opción desconocida {token}")
            else:
                errors.append(f"argumento inesperado '{token}'")
            i += 1
            continue

        kind = OPTION_KINDS[token]
        i += 1

        if kind is None:
            continue

        nargs = 2 if kind == "tcpflags" else 1
        values = tokens[i:i + nargs]

        if len(values) < nargs or any(v.startswith("-") and not v.lstrip("-").isdigit() for v in values):
            errors.append(f"falta el argumento de {token}")
            continue

        i += nargs
        value = values[0]

        problem = check_value(kind, token, value, ipv6)
        if problem:
            errors.append(problem)

        if kind == "proto":
            protocol = value.lower()
        elif kind == "match":
            matches.add(value.lower())
        elif kind == "target":
            if value not in BUILTIN_TARGETS and value not in custom_chains:
                if value.upper() in BUILTIN_TARGETS:
                    errors.append(f"destino (-j) '{value}' debe escribirse '{value.upper()}'")
                else:
                    errors.append(f"destino (-j) desconocido '{value}'")
        elif kind == "port":
            port_options.append(token)

    if operation is None:
        errors.append("falta la operación (-A, -I, -D, ...)")

    if port_options and protocol not in PORT_PROTOCOLS and not (matches & PORT_PROTOCOLS):
        errors.append(f"{port_options[0]} requiere -p tcp/udp/sctp/dccp")

    return errors

# -------------------------------------------------------------
# Validates the value of an option according to its kind.
# -------------------------------------------------------------
def check_value(kind, option, value, ipv6):
    if kind == "table":
        if value not in IPTABLES_TABLES:
            return f"tabla inválida '{value}'"

    elif kind == "proto":
        if value.lower() not in PROTOCOLS and not (value.isdigit() and int(value) <= 255):
            return f"protocolo inválido '{value}'"

    elif kind == "addr":
        return check_address(option, value, ipv6)

    elif kind == "iface":
        if not re.fullmatch(r"[a-zA-Z0-9_.:+@-]+", value):
            return f"interfaz inválida '{value}'"

    elif kind == "port":
        return check_port_range(option, value, ":")

    elif kind == "ports":
        for part in value.split(","):
            problem = check_port_range(option, part, ":")
            if problem:
                return problem

    elif kind == "natport":
        return check_port_range(option, value, "-")

    elif kind == "mark":
        if not re.fullmatch(r"(0x[0-9a-fA-F]+|\d+)(/(0x[0-9a-fA-F]+|\d+))?", value):
            return f"marca inválida '{value}' en {option}"

    elif kind == "nat":
        return check_nat_destination(option, value, ipv6)

    return None

def check_address(option, value, ipv6):
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return f"dirección inválida '{value}' en {option}"

    return check_family(option, value, network.version, ipv6)

def check_family(option, value, version, ipv6):
    if ipv6 and version == 4:
        return f"dirección IPv4 '{value}' en {option} de un comando ip6tables"
    if not ipv6 and version == 6:
        return f"dirección IPv6 '{value}' en {option} de un comando iptables"
    return None

# -------------------------------------------------------------
# Port, service name or range (separator ':' for matches, '-' for NAT).
# -------------------------------------------------------------
def check_port_range(option, value, separator):
    if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9-]*", value):
        return None  # service name

    parts = value.split(separator)
    if len(parts) > 2 or any(not p.isdigit() for p in parts):
        return f"puerto inválido '{value}' en {option}"

    numbers = [int(p) for p in parts]
    if any(n < PORT_MIN or n > PORT_MAX for n in numbers):
        return f"puerto fuera de rango ({PORT_MIN}-{PORT_MAX}) '{value}' en {option}"
    if len(numbers) == 2 and numbers[0] > numbers[1]:
        return f"rango de puertos invertido '{value}' en {option}"
    return None

# -------------------------------------------------------------
# NAT destination: addr, addr:port, addr:port-port, [v6addr]:port, port.
# -------------------------------------------------------------
def check_nat_destination(option, value, ipv6):
    address, port = value, None

    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            return f"dirección inválida '{value}' en {option}"
        address, rest = value[1:end], value[end + 1:]
        if rest:
            if not rest.startswith(":"):
                return f"destino inválido '{value}' en {option}"
            port = rest[1:]
    elif value.count(":") == 1:
        address, port = value.split(":")

    if address:
        for ip in address.split("-"):
            try:
                parsed = ipaddress.ip_address(ip)
            except ValueError:
                return f"dirección inválida '{ip}' en {option}"
            problem = check_family(option, ip, parsed.version, ipv6)
            if problem:
                return problem

    if port is not None:
        return check_port_range(option, port, "-")
    return None

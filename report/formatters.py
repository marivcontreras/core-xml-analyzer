from collections import defaultdict

from parser.devices import get_node
from utils import config_helper
from utils.ip import PREFIX_TYPE, TYPE_LABELS

# -------------------------------------------------
# Sumarizes metrics and warnings for analysis panel
# -------------------------------------------------
def summarize(data):
    return {
        "devices_total": len(data["devices"]),
        "routers": len(data["routers"]),
        "links": len(data["links"]),
        "networks": len(data["networks"]),
        "warnings": [w["message"] for w in data["warnings"]]
    }

def build_warning_summary(data, warnings, router_warnings):
    summary = {
        "total": 0,
        "by_severity": defaultdict(int),
        "by_scope": defaultdict(int)
    }

    # --------------------------------------------------
    # network warnings
    # --------------------------------------------------

    for net_name, type_groups in warnings.items():

        for warning_type, items in type_groups.items():

            summary["by_scope"]["network"] += len(items)

            for item in items:

                severity = item.get("severity", "warning")

                summary["by_severity"][severity] += 1
                summary["total"] += 1

    # --------------------------------------------------
    # router config warnings
    # --------------------------------------------------

    for router_name, type_groups in router_warnings.items():

        for warning_type, items in type_groups.items():

            summary["by_scope"]["router_config"] += len(items)

            for item in items:

                severity = item.get("severity", "warning")

                summary["by_severity"][severity] += 1
                summary["total"] += 1

    # --------------------------------------------------
    # routing/tunnel/isp warnings
    # --------------------------------------------------

    for routing in data.get("routing", {}).values():

        for category, items in routing.get("warnings", {}).items():

            summary["by_scope"][category] += len(items)

            for item in items:

                severity = item.get("severity", "warning")

                summary["by_severity"][severity] += 1
                summary["total"] += 1

    return summary

def _format_grouped_warning(router_name, category, code, prefix_type, items):
    #print(f"Formatting grouped warning for router {router_name}, category {category}, code {code}, prefix_type {prefix_type}, items: {items}")
    severity = items[0].get("severity", "warning").upper()
    label_type = TYPE_LABELS.get(severity, severity)
    label_code = TYPE_LABELS.get(code.upper(), code.upper()) if code else "UNKNOWN"
    prefix_type = prefix_type.upper() if prefix_type else None

    if len(items) == 1:
        message = items[0].get("message")
    else:
        route_names = sorted({item.get("route") for item in items if item.get("route")})
        tables = sorted({item.get("table") for item in items if item.get("table")})
        messages = sorted({item.get("message") for item in items if item.get("message")})

        if code == "unreachable_network" and prefix_type and route_names:
            if prefix_type != None:  
                message = f"{prefix_type}: Desde {router_name} no se pueden alcanzar las redes  {', '.join(route_names)}"
            else:
                message = f"Desde {router_name} no se pueden alcanzar las redes: {', '.join(route_names)}"
        
        elif code == "missing_route_additional_table" and prefix_type and route_names:
            table_text = tables[0] if len(tables) == 1 else "varias tablas"
            if (table_text == "to-R3"):
                message = f"En {router_name} no se encontró tabla adicional con las rutas para redireccionar paquetes TCP hacia R3 con origen en las redes {prefix_type}: {', '.join(route_names)}."
            elif (table_text == "guest-isolation"):
                message = f"{prefix_type}: En {router_name} no se encontró tabla adicional con las rutas para redirir el trafico originado en Wguest."
            else:
                message = f"En {router_name} no se encontraron las rutas para {table_text} hacia las redes {prefix_type}: {', '.join(route_names)}"
        
        elif code == "invalid_route_field_via_info" and route_names:
            if prefix_type != None:
                message = f"{prefix_type}: En {router_name} hay información inválida en el campo via en las rutas hacia las redes {', '.join(route_names)}"
            else:
                message = f"En {router_name} hay información inválida en el campo via en las rutas hacia las redes: {', '.join(route_names)}"

        elif code == "invalid_route_field_via_info_none" and route_names:
            if prefix_type != None:
                message = f"{prefix_type}: {router_name} tiene rutas donde se están utilizando direcciones inválidas o no asignadas en el campo via hacia las redes {', '.join(route_names)}"
            else:
                message = f"{router_name} tiene rutas donde se están utilizando direcciones inválidas o no asignadas en el campo via hacia las redes: {', '.join(route_names)}"

        elif code == "invalid_route_field_default" and route_names:
            if prefix_type != None: 
                message = f"{prefix_type}: En {router_name}, los paquetes dirigidos hacia las redes  {', '.join(route_names)} están siendo direccionados incorrectamente a través de la entrada por default"
            else:
                message = f"En {router_name}, los paquetes dirigidos hacia las redes: {', '.join(route_names)} están siendo direccionados incorrectamente a través de la entrada por default"
        
        elif code == "invalid_route_field_minimization" and route_names:
            message = f"{prefix_type}: Router {router_name} tiene {len(route_names)} advertencias de minimización por default no realizada para rutas: {', '.join(route_names)}"

        elif route_names:
            message = f"Router {router_name} tiene {len(route_names)} advertencias '{code}' para rutas: {', '.join(route_names)}"
        
        else:
            message = f"Router {router_name} tiene {len(messages)} advertencias '{code}': {'; '.join(messages)}"

    label_category = TYPE_LABELS.get(category, category) if category else label_code

    formatted = (
        f"[{label_type}] "
        f"[{label_category}] "
        f"[{router_name}] "
        f"{message}"
    )

    return [formatted]

def build_text_warning_summary(data, grouped_warnings, router_warnings):
    lines = []    

    # --------------------------------------------------
    # router config warnings
    # --------------------------------------------------
    for router_name, type_groups in router_warnings.items():

        for warning_type, items in type_groups.items():

            for item in items:

                severity = item.get("severity", "warning").upper()

                lines.append(
                    (
                        f"[{TYPE_LABELS.get(severity, severity)}] "
                        f"[{TYPE_LABELS.get(warning_type, warning_type)}] "
                        f"[{router_name}] "
                        f"{item.get('message')}"
                    )
                )

    # --------------------------------------------------
    # routing / tunnel / isp warnings
    # --------------------------------------------------

    routing_groups = {}

    for node_id, routing in data.get("routing", {}).items():
        node = get_node(data, node_id)
        router_name = node.get("name", node_id)

        for category, items in routing.get("warnings", {}).items():
            for item in items:
                #print(f"Processing routing warning for router {router_name}, category {category}, item: {item}")
                code = item.get("code") or item.get("type")
                prefix_type = item.get("prefix_type")
                key = (router_name, category, code, prefix_type)
                routing_groups.setdefault(key, []).append(item)

    for (router_name, category, code, prefix_type), grouped_items in routing_groups.items():
        lines.extend(_format_grouped_warning(router_name, category, code, prefix_type, grouped_items))

    return lines

# ------------------------------------
# Formats networks for networks panel
# ------------------------------------
def format_network_name(name):
    return config_helper.format_network_name(name)


def pretty_networks(data):
    rows = []

    for _, net in data["networks"].items():
        rows.append({
            "name": net["name"],
            "kind": net["kind"],
            "members": net["members"],
            "prefixes": net["prefixes"],
            "prefix_sources": net.get("prefix_sources", {})
        })

    return rows

# --------------------------------------
# Groups warnings by router
# --------------------------------------
def get_router_config_warnings(data):
    result = {}

    for w in data["warnings"]:
        # only node-scoped warnings
        if w.get("scope") != "node" and w.get("scope") != "interface":
            continue

        node = w.get("node", "Desconocido")

        if node not in result:
            result[node] = []

        result[node].append(w)

    return result

# --------------------------------------
# Groups warnings by type
# --------------------------------------
def group_router_warnings_by_type(data):
    raw = get_router_config_warnings(data)
    grouped = {}

    for node, warnings in raw.items():
        grouped[node] = {}

        for w in warnings:
            wtype = w.get("type", "generic")

            if wtype not in grouped[node]:
                grouped[node][wtype] = []

            grouped[node][wtype].append(w)

    return grouped

# --------------------------------------
# Groups warnings by network and type
# --------------------------------------
def group_warnings(data):
    grouped = {}

    for w in data["warnings"]:
        net = w.get("network", PREFIX_TYPE["global"])
        wtype = w.get("type", "generic")

        if net not in grouped:
            grouped[net] = {}

        if wtype not in grouped[net]:
            grouped[net][wtype] = []

        grouped[net][wtype].append(w)

    return grouped

# ---------------------------------------------------
# Deletes comments from text, 
# both full-line and inline comments starting with #
# ---------------------------------------------------
# These generic text helpers now live in utils.text; re-exported here so
# existing `from report.formatters import ...` call sites keep working.
from utils.text import (  # noqa: E402,F401
    strip_comments,
    format_via_info,
    format_route,
    reverse_network_name,
)

# -------------------------------------------------------------
# Builds a matrix table for displaying network information
# -------------------------------------------------------------
def build_matrix_table(matrix, networks_data, validation_result=None):

    import copy
    intranet_routers = config_helper.get_config().get("devices", {}).get("intranet_routers", [])
    routers = [r for r in matrix.keys() if r in intranet_routers]

    validation_table = {}
    warnings = []
    grouped_warnings = {}

    if validation_result:
        validation_table = validation_result.get("validation_table", {})
        warnings = validation_result.get("warnings", [])
        grouped_warnings = validation_result.get("grouped_warnings", {})

    # ----------------------------------------------------------
    # collect networks
    # ----------------------------------------------------------

    networks = set()

    for r in matrix.values():
        networks.update(r.keys())

    # ----------------------------------------------------------
    # filter networks
    # ----------------------------------------------------------

    networks = sorted(n for n in networks if config_helper.is_intranet_network(n))

    network_prefixes = {}

    for net in networks_data.values():
        net_name = net.get("name")
        network_prefixes[net_name] = [p for p in net.get("prefixes", []) if p != "-"]

    rows = []

    for net in networks:

        row = {
            "network": net,
            "prefixes": network_prefixes.get(net, []),
            "values": {},
            "validation": {}
        }

        has_data = False

        for router in routers:

            cell = matrix.get(router, {}).get(net)

            validation = validation_table.get(router, {}).get(net, validation_table.get(router, {}).get(reverse_network_name(net), build_empty_validation()))

            # --------------------------------------------------
            # normalize routing entries to list
            # renderer should always receive same structure
            # --------------------------------------------------

            if cell is None:
                normalized_cell = []

            elif isinstance(cell, list):
                normalized_cell = copy.deepcopy(cell)

            else:
                normalized_cell = [copy.deepcopy(cell)]

            if normalized_cell:
                has_data = True

            row["values"][router] = normalized_cell
            row["validation"][router] = validation

        if has_data:
            rows.append(row)

    return {
        "routers": routers,
        "rows": rows,
        "warnings": warnings,
        "grouped_warnings": grouped_warnings
    }

# --------------------------------------------
# Builds an empty validation result structure
# --------------------------------------------
def build_empty_validation():
    return {
        "exists": True,
        "valid": True,
        "field_validation": {},
        "matched_routes": [],
        "missing_expected_routes": [],
        "extra_routes": []
    }

# ---------------------------
# Groups warnings by router
# ---------------------------
def group_warnings_by_router(warnings):
    grouped = defaultdict(list)

    for warning in warnings:
        router = warning.get("router", "Unknown")
        grouped[router].append(warning)

    return dict(grouped)
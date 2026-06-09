from parser.devices import INTRANET_ROUTERS, get_node
from collections import defaultdict

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

from collections import defaultdict

def build_warning_summary2(data, warnings, router_warnings):
    summary = {
        "total": 0,
        "by_severity": defaultdict(int),
        "by_category": defaultdict(int)
    }

    # --------------------------------------------------
    # network warnings
    # --------------------------------------------------

    for net_name, type_groups in warnings.items():

        for warning_type, items in type_groups.items():

            summary["by_category"][warning_type] += len(items)

            for item in items:

                severity = item.get("severity", "warning")

                summary["by_severity"][severity] += 1
                summary["total"] += 1

    # --------------------------------------------------
    # router warnings
    # --------------------------------------------------

    for router_name, type_groups in router_warnings.items():

        for warning_type, items in type_groups.items():

            summary["by_category"][warning_type] += len(items)

            for item in items:

                severity = item.get("severity", "warning")

                summary["by_severity"][severity] += 1
                summary["total"] += 1

    # --------------------------------------------------
    # parsed routing/tunnel/isp warnings
    # --------------------------------------------------

    for routing in data.get("routing", {}).values():

        for category, items in routing.get("warnings", {}).items():

            summary["by_category"][category] += len(items)

            for item in items:

                severity = item.get("severity", "warning")

                summary["by_severity"][severity] += 1
                summary["total"] += 1

    return summary


from collections import defaultdict

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

    if len(items) == 1:
        message = items[0].get("message")
    else:
        route_names = sorted({item.get("route") for item in items if item.get("route")})
        tables = sorted({item.get("table") for item in items if item.get("table")})
        messages = sorted({item.get("message") for item in items if item.get("message")})

        if code == "unreachable_network" and prefix_type and route_names:
            prefix_lower = prefix_type.lower() if isinstance(prefix_type, str) else None
            display_prefix = prefix_type.upper() if isinstance(prefix_type, str) else prefix_type
            if prefix_lower == "global":
                message = f"Desde {router_name} no se pueden alcanzar las redes {display_prefix}: {', '.join(route_names)}"
            elif prefix_type is not None:  
                message = f"Desde {router_name} no se pueden alcanzar las redes {display_prefix}: {', '.join(route_names)}"
            else:
                message = f"Desde {router_name} no se pueden alcanzar las redes: {', '.join(route_names)}"
        
        elif code == "missing_route_additional_table" and prefix_type and route_names:
            prefix_lower = prefix_type.lower() if isinstance(prefix_type, str) else None
            display_prefix = prefix_type.upper() if isinstance(prefix_type, str) else prefix_type
            prefix_display_text = display_prefix if prefix_lower != "global" else display_prefix
            table_text = tables[0] if len(tables) == 1 else "varias tablas"
            if (table_text == "to-R3"):
                message = f"En {router_name} no se encontró tabla adicional con las rutas para redireccionar paquetes TCP hacia R3 con origen en las redes {prefix_display_text}: {', '.join(route_names)}. Chequear configuración de ip rule/iptables por si existen implementaciones alternativas."
            elif (table_text == "guest-isolation"):
                message = f"En {router_name} no se encontró tabla adicional con las rutas para prohibir el acceso desde Wguest hacia las redes {prefix_display_text}: {', '.join(route_names)}. Chequear configuración de ip rule/iptables por si existen implementaciones alternativas."
            else:
                message = f"En {router_name} no se encontraron las rutas para {table_text} hacia las redes {prefix_display_text}: {', '.join(route_names)}"
        
        elif code == "invalid_route_field_via_info" and route_names:
            if prefix_type != None:
                message = f"Desde {router_name} hay información inválida en el campo via en las rutas hacia las redes {prefix_type}: {', '.join(route_names)}"
            else:
                message = f"Desde {router_name} hay información inválida en el campo via en las rutas hacia las redes: {', '.join(route_names)}"
        
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
def pretty_networks(data):
    rows = []

    for _, net in data["networks"].items():
        rows.append({
            "name": net["name"],
            "kind": net["kind"],
            "members": net["members"],
            "prefixes": net["prefixes"]
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

        node = w.get("node", "unknown")

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
# Composses via information into a readable string
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
            text += f" en red {network}"

        formatted.append(text)

    return " | ".join(formatted)

# -------------------------------------------------
# Composses route information into a readable string
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

# -------------------------------------------------------------
# Checks if a network name corresponds to an intranet network
# -------------------------------------------------------------
def is_intranet_network(net_name):
    # 1. incluir p2p SI ambos extremos son intranet
    if "<>" in net_name:
        parts = [p.strip() for p in net_name.split("<>")]
        return all(p in INTRANET_ROUTERS for p in parts)

    # 2. excluir cosas obvias
    if net_name.lower() in ["default", "internet", "isp"]:
        return False

    # 3. redes LAN/WiFi por nombre (ajustable)
    intranet_keywords = [
        "SwDataCenter", "WVentas", "SwVentas",
        "WGuest", "SwAdmin", "SwOfiAdmin"
    ]

    return any(k in net_name for k in intranet_keywords)

# -------------------------------------------------------------
# Builds a matrix table for displaying network information
# -------------------------------------------------------------
def build_matrix_table(matrix, networks_data, validation_result=None):

    import copy

    routers = [r for r in matrix.keys() if r in INTRANET_ROUTERS]

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

    networks = sorted(n for n in networks if is_intranet_network(n))

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
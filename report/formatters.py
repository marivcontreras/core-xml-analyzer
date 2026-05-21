from parser.devices import INTRANET_ROUTERS
from collections import defaultdict

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
        net = w.get("network", "global")
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
            return "Dirección IP inexistente en la topología"
        
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

    route_type = route.get("type")    
    dst = route.get("dst")
    table = route.get("table")
    dev = route.get("dev")
    via_info = route.get("via_info")
    
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
def reverse_route_name(route_name):
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
    routers = [r for r in matrix.keys() if r in INTRANET_ROUTERS]

    validation_table = {}
    warnings = []

    if validation_result:
        validation_table = validation_result.get("validation_table", {})
        warnings = validation_result.get("warnings", [])
        grouped_warnings = validation_result.get("grouped_warnings", [])

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
            validation = (validation_table.get(router, {}).get(net, build_empty_validation()))

            # --------------------------------------------------
            # normalize routing entries to list
            # renderer should always receive same structure
            # --------------------------------------------------

            if cell is None:
                normalized_cell = []
            elif isinstance(cell, list):
                normalized_cell = cell
            else:
                normalized_cell = [cell]

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
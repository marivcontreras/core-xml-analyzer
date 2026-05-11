def summarize(data):
    return {
        "devices_total": len(data["devices"]),
        "routers": len(data["routers"]),
        "links": len(data["links"]),
        "networks": len(data["networks"]),
        "warnings": [w["message"] for w in data["warnings"]]  # 👈 mantiene compatibilidad
    }


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

def format_cell(cell):
    if not cell:
        return "-"

    parts = []

    parts = [cell.get("type", "-")]

    if cell.get("via"):
        via = cell["via"]

        if cell.get("via_info"):
            info = cell["via_info"]
            via = f"{via} ({info['node']}-{info['interface']})"

        parts.append(f"via {via}")


    if cell.get("table"):
        parts.append(f"table {cell['table']}")

    return "<br>".join(parts)

INTRANET_ROUTERS = {"R1-DC", "R2", "R3", "R4", "R5", "R6"}

def reverse_route_name(route_name):
    if "<>" in route_name:
        parts = [p.strip() for p in route_name.split("<>")]
        if len(parts) == 2:
            return f"{parts[1]}<>{parts[0]}"
    return route_name

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

def build_matrix_table(matrix, validation_result=None):
    routers = [r for r in matrix.keys() if r in INTRANET_ROUTERS]

    validation_table = {}
    warnings = []

    if validation_result:
        validation_table = validation_result.get("validation_table", {})
        warnings = validation_result.get("warnings", [])

    # ----------------------------------------------------------
    # collect networks
    # ----------------------------------------------------------

    networks = set()

    for r in matrix.values():
        networks.update(r.keys())

    # ----------------------------------------------------------
    # filter networks
    # ----------------------------------------------------------

    networks = sorted(
        n for n in networks
        if is_intranet_network(n)
    )

    rows = []

    for net in networks:

        row = {
            "network": net,
            "values": {},
            "validation": {}
        }

        has_data = False

        for router in routers:

            cell = matrix.get(router, {}).get(net)

            validation = (
                validation_table
                    .get(router, {})
                    .get(net, build_empty_validation())
            )

            #print(f"Processing cell for router {router}, network {net}, validation: {validation}")
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
        "warnings": warnings
    }


def build_empty_validation():
    return {
        "exists": True,
        "valid": True,
        "field_validation": {},
        "matched_routes": [],
        "missing_expected_routes": [],
        "extra_routes": []
    }
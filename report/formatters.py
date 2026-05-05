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
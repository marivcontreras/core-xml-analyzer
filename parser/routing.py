import ipaddress

from utils.ip import PREFIX_TYPE, classify_prefix_type
from analyzer.prefixes import get_staticroute_interface_addresses
from parser.devices import get_node, is_intranet_router
from report.formatters import is_intranet_network

# ----------------------------------------------------------
# Returns normalized IP network object, treating "default" as a special case.
# ----------------------------------------------------------
def normalize_route_network(value):
    if value == PREFIX_TYPE["default"]:
        return ipaddress.ip_network("::/0")

    return ipaddress.ip_network(value, strict=False)

# -------------------------------------------------------------------------
# Calculates longest-prefix-match score between: route_dst vs target_prefix
# Higher score = more specific route.
# -------------------------------------------------------------------------
def calculate_lpm_score(route_dst, target_prefix):

    if not route_dst or not target_prefix:
        return None

    try:
        route_network = normalize_route_network(route_dst)
        target_network = normalize_route_network(target_prefix)

    except Exception:
        return None

    # ------------------------------------------------------
    # Different IP family
    # ------------------------------------------------------

    if route_network.version != target_network.version:
        return None

    # ------------------------------------------------------
    # Exact match
    # ------------------------------------------------------

    if route_network == target_network:
        return route_network.prefixlen

    # ------------------------------------------------------
    # Route contains target
    #
    # route:   2001::/48
    # target:  2001::1/64
    # ------------------------------------------------------

    if target_network.subnet_of(route_network):
        return route_network.prefixlen

    # ------------------------------------------------------
    # No match
    # ------------------------------------------------------

    return None

# -------------------------------------------------------------------------
# Finds the best matching route PER TABLE for a single target prefix.
# -------------------------------------------------------------------------
def find_best_routes_by_table(routes, target_prefix):
    best_routes = {}

    for route in routes:

        dst = route.get("dst")

        if not dst:
            continue

        table = route.get("table", "main")

        score = calculate_lpm_score(dst, target_prefix)

        if score is None:
            continue

        current = best_routes.get(table)

        if (current is None or score > current["score"]):
            best_routes[table] = {
                "route": route,
                "score": score
            }

    return best_routes

# -----------------------------------------------
# Classifies route type based on its attributes.
# -----------------------------------------------
def classify_route(route):
    rtype = route.get("type")

    # 1. bloqueos explícitos
    if rtype in ["blackhole", "prohibit", "unreachable"]:
        return rtype

    dst = route.get("dst")
    table = route.get("table", "main")

    # 3. policy routing
    if table != "main":
        return "policy"

    # 4. indirect normal
    if route.get("via"):
        return "IND"

    # fallback raro
    return "unknown"

# ------------------------------------------------------------------------
# Returns true if router belongs to the network, based on network members.
# ------------------------------------------------------------------------
def router_belongs_to_network(router_name, net):
    members = net.get("members", [])
    return router_name in members

# -------------------------------------------------------------------
# Returns interface of the node that connects to the network, if any.
# -------------------------------------------------------------------
def find_interface_to_network(node_id, net, data):
    net_name = net.get("name")

    for link in data.get("links", []):

        node1 = link.get("node1")
        node2 = link.get("node2")

        iface1 = link.get("iface1")
        iface2 = link.get("iface2")

        # -------------------------------------------------
        # Normal network object connection
        # Router <-> Switch/LAN/etc
        # -------------------------------------------------

        if node1 == node_id:
            other = get_node(data, node2)

            if other and other.get("name") == net_name:
                return iface1.get("name") if iface1 else None

        if node2 == node_id:
            other = get_node(data, node1)

            if other and other.get("name") == net_name:
                return iface2.get("name") if iface2 else None

        # -------------------------------------------------
        # P2P network support
        # Network represented by the link itself
        # Example: "R4 <-> R5"
        # -------------------------------------------------

        if (node1 == node_id or node2 == node_id):
            n1 = get_node(data, node1)
            n2 = get_node(data, node2)

            if not n1 or not n2:
                continue

            p2p_name_a = f"{n1.get('name')}<>{n2.get('name')}"
            p2p_name_b = f"{n2.get('name')}<>{n1.get('name')}"

            if net_name in [p2p_name_a, p2p_name_b]:

                if node1 == node_id:
                    return iface1.get("name") if iface1 else None

                if node2 == node_id:
                    return iface2.get("name") if iface2 else None

    return None

# -------------------------------------------------------------------
# Returns node and interface information for a given IP address.
# -------------------------------------------------------------------
def resolve_ip_owner(ip_str, data):
    try:
        ip = ipaddress.ip_address(ip_str)
    except:
        return None

    for net in data["networks"].values():
        for member in net.get("member_interfaces", []):
            node_id = member["node"]
            iface = member["iface"]
            addrs = get_staticroute_interface_addresses(data, node_id, iface)
            for addr in addrs:
                if addr.ip == ip:
                    node = data["devices"].get(node_id, {"name": f"node{node_id}"})

                    return {
                        "node": node["name"],
                        "interface": iface,
                        "network": net["name"],
                        "type": "neighbor"
                    }

    return {
                "node": None,
                "interface": None,
                "network": None,
                "type": None
            }

# -------------------------------------------------------------------
# Buids the routing matrix for all intranet routers and networks, 
# classifying routes and resolving via information.
# -------------------------------------------------------------------
def build_routing_matrix(data, intranet = True):
    matrix = {}

    for node_id, routing in data.get("routing", {}).items():
        device = data["devices"].get(node_id)

        if not device:
            continue

        router_name = device.get("name")

        # 🔒 solo routers de intranet
        if intranet:
            if not is_intranet_router(router_name):
                continue
        else:
            if is_intranet_router(router_name):
                continue
        
        matrix[router_name] = {}
        routes = routing.get("routes", [])

        for net in data.get("networks", {}).values():
            net_name = net.get("name")

            if intranet:
                if not is_intranet_network(net_name):
                    continue
            else:
                if is_intranet_network(net_name):
                    continue

            prefixes = [p for p in net.get("prefixes", []) if p != "-"]

            # siempre inicializar lista
            matrix[router_name][net_name] = []

            # --------------------------------------------------
            # 1. DIRECT ROUTE
            # --------------------------------------------------

            is_direct = router_belongs_to_network(router_name, net)

            if is_direct:
                for prefix in prefixes:
                    matrix[router_name][net_name].append(
                        build_route(
                            "DIR",
                            via=None,
                            via_info=None,
                            dev=find_interface_to_network(node_id, net, data),
                            table="local",
                            dst=prefix,
                            net_prefix=prefix,
                            prefix_type=classify_prefix_type(prefix),
                            score=999,
                            is_default=False,
                            is_policy=False
                        )
                    )

            # --------------------------------------------------
            # 2. INDIRECT ROUTES (una mejor ruta por tabla)
            # --------------------------------------------------
            for prefix in prefixes:

                best_routes = find_best_routes_by_table(routes, prefix)

                for table_name, best_route in best_routes.items():

                    # si no existen rutas válidas, o la mejor ruta en main es la directa no agrego indirectas
                    if not best_route or (table_name == "main" and is_direct):
                        continue

                    route = best_route["route"]

                    via = route.get("via")

                    via_info = None

                    if via:
                        via_info = resolve_ip_owner(via, data)

                    matrix[router_name][net_name].append(
                        build_route(
                            classify_route(route),
                            via=via,
                            via_info=via_info,
                            dev=route.get("dev"),
                            table=table_name,
                            dst=route.get("dst"),
                            net_prefix=prefix,
                            prefix_type=classify_prefix_type(prefix),
                            score=best_route["score"],
                            is_default=route.get("dst") in ["default", "::/0"],
                            is_policy=table_name != "main"
                        ))

            # --------------------------------------------------
            # 3. limpiar redes sin rutas
            # --------------------------------------------------

            if not matrix[router_name][net_name]:
                matrix[router_name][net_name] = None

    return matrix


def build_route(route_type, dev=None, via=None, via_info=None, table="main", dst=None, net_prefix=None, prefix_type=None, score=0, is_default=False, is_policy=False):
    return {
        "type": route_type,
        "net_prefix": net_prefix,
        "prefix_type": prefix_type,
        "dst": dst, 
        "via": via,
        "via_info": via_info,
        "dev": dev,
        "table": table,
        "score": score,
        "is_default": is_default,
        "is_policy": is_policy
    }


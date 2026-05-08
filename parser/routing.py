
import ipaddress

from analyzer.prefixes import get_staticroute_interface_addresses
from parser.l2 import get_node
from report.formatters import is_intranet_network

def calculate_lpm_score(route_dst, network_prefixes):
    """
    Returns the best LPM score for a route against a list
    of network prefixes.

    Higher = more specific match.

    Examples:
        route_dst = "2001:db8::/64"
        network_prefixes = [
            "2001:db8::/64",
            "2001:db8:1::/64"
        ]

        -> 64

    Supports:
    - exact prefix matches
    - default routes (::/0)
    - overlapping prefixes
    - IPv4 and IPv6
    """

    if not route_dst:
        return None

    try:
        route_network = ipaddress.ip_network(
            route_dst,
            strict=False
        )

    except Exception:
        return None

    best_score = None

    for prefix in network_prefixes:

        try:
            candidate_network = ipaddress.ip_network(
                prefix,
                strict=False
            )

        except Exception:
            continue

        # Different IP family
        if (
            route_network.version !=
            candidate_network.version
        ):
            continue

        # --------------------------------------------------
        # Exact match
        # --------------------------------------------------

        if route_network == candidate_network:
            score = route_network.prefixlen

        # --------------------------------------------------
        # Route contains candidate
        # Example:
        #   route: 2001::/48
        #   candidate: 2001::1/64
        # --------------------------------------------------

        elif candidate_network.subnet_of(route_network):
            score = route_network.prefixlen

        # --------------------------------------------------
        # Route is more specific than candidate
        # Example:
        #   route: 2001::1/64
        #   candidate: 2001::/48
        # --------------------------------------------------

        elif route_network.subnet_of(candidate_network):
            score = route_network.prefixlen

        else:
            continue

        if best_score is None or score > best_score:
            best_score = score

    return best_score

def find_best_routes_by_table(routes, prefixes):
    best_routes = {}

    for route in routes:

        dst = route.get("dst")

        if not dst:
            continue

        table = route.get("table", "main")

        score = calculate_lpm_score(
            dst,
            prefixes
        )

        if score is None:
            continue

        current = best_routes.get(table)

        if (
            current is None or
            score > current["score"]
        ):
            best_routes[table] = {
                "route": route,
                "score": score
            }

    return best_routes


def classify_route(route):
    rtype = route.get("type")

    # 1. bloqueos explícitos
    if rtype in ["blackhole", "prohibit", "unreachable"]:
        return rtype

    dst = route.get("dst")
    table = route.get("table", "main")

    # 2. default
    if dst in ["default", "::/0", "0.0.0.0/0"]:
        if table != "main":
            return "policy-default"
        return "default"

    # 3. policy routing
    if table != "main":
        return "policy"

    # 4. indirect normal
    if route.get("via"):
        return "indirect"

    # fallback raro
    return "unknown"

INTRANET_ROUTERS = {"R1-DC", "R2", "R3", "R4", "R5", "R6"}

def is_intranet_router(router):
    return router in INTRANET_ROUTERS

def route_match_score(route_dst, network_prefix):
    """
    Devuelve el prefixlen si matchea, o -1 si no matchea.
    Sirve para elegir el mejor match (LPM).
    """

    if not route_dst:
        return -1

    # default = peor match posible, pero válido
    if route_dst in ["default", "::/0", "0.0.0.0/0"]:
        return 0

    try:
        route_net = ipaddress.ip_network(route_dst, strict=False)
        net = ipaddress.ip_network(network_prefix, strict=False)
    except:
        return -1

    if net.subnet_of(route_net) or net == route_net:
        return route_net.prefixlen  # 👈 clave para LPM

    return -1

def find_best_route(routes, prefixes):
    best_route = None
    best_score = -1

    for route in routes:
        dst = route.get("dst")

        for p in prefixes:
            score = route_match_score(dst, p)

            if score > best_score:
                best_score = score
                best_route = route

    return { "route": best_route,
             "score": best_score
        } 

def router_belongs_to_network(router_name, net, data):
    net_name = net.get("name")

    # miembros de la red (ya los tenés en infer_networks)
    members = net.get("members", [])

    return router_name in members

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

        if (
            node1 == node_id or
            node2 == node_id
        ):
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

def resolve_ip_owner(ip_str, data):
    try:
        ip = ipaddress.ip_address(ip_str)
    except:
        return None

    for net in data["networks"].values():
        for member in net.get("member_interfaces", []):
            node_id = member["node"]
            iface = member["iface"]

            addrs = get_staticroute_interface_addresses(node_id, iface, data)

            for addr in addrs:
                if addr.ip == ip:
                    node = data["devices"].get(node_id, {"name": f"node{node_id}"})

                    return {
                        "node": node["name"],
                        "interface": iface,
                        "network": net["name"],
                        "type": "neighbor"
                    }

    return None

def build_routing_matrix(data):
    matrix = {}

    for node_id, routing in data.get("routing", {}).items():
        device = data["devices"].get(node_id)

        if not device:
            continue

        router_name = device.get("name")

        # 🔒 solo routers de intranet
        if not is_intranet_router(router_name):
            continue

        matrix[router_name] = {}

        routes = routing.get("routes", [])

        for net in data.get("networks", {}).values():
            net_name = net.get("name")

            if not is_intranet_network(net_name):
                continue

            prefixes = [
                p for p in net.get("prefixes", [])
                if p != "-"
            ]

            # siempre inicializar lista
            matrix[router_name][net_name] = []

            # --------------------------------------------------
            # 1. DIRECT ROUTE
            # --------------------------------------------------

            is_direct = router_belongs_to_network(
                router_name,
                net,
                data
            )

            if is_direct:
                matrix[router_name][net_name].append({
                    "type": "direct",
                    "via": None,
                    "via_info": None,
                    "dev": find_interface_to_network(
                        node_id,
                        net,
                        data
                    ),
                    "table": "local",
                    "dst": None,
                    "score": 999,
                    "is_default": False,
                    "is_policy": False
                })

            # --------------------------------------------------
            # 2. INDIRECT ROUTES
            #    (una mejor ruta por tabla)
            # --------------------------------------------------

            best_routes = find_best_routes_by_table(
                routes,
                prefixes
            )

            for table_name, best_route in best_routes.items():

                if not best_route:
                    continue

                route = best_route["route"]

                via = route.get("via")

                via_info = None

                if via:
                    via_info = resolve_ip_owner(
                        via,
                        data
                    )

                matrix[router_name][net_name].append({
                    "type": classify_route(route),
                    "via": via,
                    "via_info": via_info,
                    "dev": route.get("dev"),
                    "table": table_name,
                    "dst": route.get("dst"),
                    "score": best_route["score"],
                    "is_default": route.get("dst") in ["default", "::/0"],
                    "is_policy": table_name != "main"
                })

            # --------------------------------------------------
            # 3. limpiar redes sin rutas
            # --------------------------------------------------

            if not matrix[router_name][net_name]:
                matrix[router_name][net_name] = None

    return matrix



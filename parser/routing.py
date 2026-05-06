
import ipaddress

from parser.l2 import get_node

def classify_route(route):
    if route.get("type") in ["blackhole", "unreachable", "prohibit"]:
        return route["type"]

    if route.get("dst") == "default":
        return "default"

    if route.get("via"):
        return "indirect"

    return "direct"

INTRANET_ROUTERS = {"R1-DC", "R2", "R3", "R4", "R5", "R6"}

def is_intranet_router(router):
    return router in INTRANET_ROUTERS


def is_intranet_network(net_name):
    # p2p internos
    if "<->" in net_name:
        r1, r2 = [r.strip() for r in net_name.split("<->")]
        return r1 in INTRANET_ROUTERS and r2 in INTRANET_ROUTERS

    # excluir externos
    if net_name.lower() in ["default", "internet", "isp"]:
        return False

    # LAN/WiFi internas
    keywords = [
        "DataCenter", "WVentas", "SwVentas",
        "WGuest", "SwAdmin", "SwOfiAdmin"
    ]
    return any(k in net_name for k in keywords)

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
        if link["node1"] == node_id:
            other = get_node(data, link["node2"])
            if other.get("name") == net_name:
                iface = link.get("iface1")
                return iface.get("name") if iface else None

        if link["node2"] == node_id:
            other = get_node(data, link["node1"])
            if other.get("name") == net_name:
                iface = link.get("iface2")
                return iface.get("name") if iface else None

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

            prefixes = [p for p in net.get("prefixes", []) if p != "-"]

            # --------------------------------------------------
            # 1. DIRECT ROUTE (por pertenencia a la red)
            # --------------------------------------------------
            is_direct = router_belongs_to_network(router_name, net, data)

            if is_direct:
                matrix[router_name][net_name] = {
                    "type": "direct",
                    "via": None,
                    "dev": find_interface_to_network(node_id, net, data),
                    "table": "local",
                    "dst": None,
                    "score": 999  # más alto que cualquier LPM
                }
                continue  # 🔥 clave: no buscar en rutas

            # --------------------------------------------------
            # 2. INDIRECT ROUTE (LPM)
            # --------------------------------------------------
            best_route = find_best_route(routes, prefixes)

            if best_route:
                matrix[router_name][net_name] = {
                    "type": classify_route(best_route["route"]),
                    "via": best_route["route"].get("via"),
                    "dev": best_route["route"].get("dev"),
                    "table": best_route["route"].get("table", "main"),
                    "dst": best_route["route"].get("dst"),
                    "score": best_route["score"]
                }
            else:
                matrix[router_name][net_name] = None

    return matrix
import ipaddress

from parser.devices import get_node
from utils.warning import add_routing_warning

# -------------------------------------------------------------
# Returns true if the route is an indirect (via) unicast entry
# that can take part in minimization (not the default entry).
# -------------------------------------------------------------
def is_minimizable_indirect(route):
    via = route.get("via")
    return (
        route.get("type") == "unicast"
        and route.get("dst") not in (None, "default")
        and via not in (None, "-")
        and route.get("dev") is not None
    )

# -------------------------------------------------------------
# Smallest network that contains every given network.
# -------------------------------------------------------------
def smallest_enclosing_block(networks):
    block = networks[0]

    while not all(net.version == block.version and net.subnet_of(block) for net in networks):
        block = block.supernet()

    return block

# -------------------------------------------------------------
# Checks, for each router, whether its routing table could be minimized
# considering entries with the same via and dev:
# 1) indirect entries matching the via/dev of the default entry are redundant.
# 2) indirect entries sharing via/dev can be summarized in a single block.
# -------------------------------------------------------------
def validate_routing_minimization(data):
    for node_id, router_data in data.get("routing", {}).items():
        router_name = get_node(data, node_id).get("name", node_id)
        routes = [r for r in router_data.get("routes", []) if r]

        defaults = {
            (r.get("family"), r.get("table")): r
            for r in routes
            if r.get("dst") == "default" and r.get("type") == "unicast"
        }

        remaining = []

        # --------------------------------------------------
        # case 1: indirect entries equal to the default entry
        # --------------------------------------------------
        for route in routes:
            if not is_minimizable_indirect(route):
                continue

            default = defaults.get((route.get("family"), route.get("table")))

            if default and default.get("via") == route["via"] and default.get("dev") == route["dev"]:
                add_routing_warning(
                    router_data,
                    "routing",
                    "minimization_default",
                    router_name=router_name,
                    route_id=route.get("id"),
                    dst=route["dst"],
                    via=route["via"],
                    dev=route["dev"]
                )
                route["has_warnings"] = True
            else:
                remaining.append(route)

        # --------------------------------------------------
        # case 2: indirect entries with same via and dev
        # --------------------------------------------------
        groups = {}
        for route in remaining:
            key = (route.get("family"), route.get("table"), route["via"], route["dev"])
            groups.setdefault(key, []).append(route)

        for (_, _, via, dev), group in groups.items():
            if len(group) < 2:
                continue

            try:
                networks = [ipaddress.ip_network(r["dst"], strict=False) for r in group]
                block = smallest_enclosing_block(networks)
            except ValueError:
                continue

            add_routing_warning(
                router_data,
                "routing",
                "minimization_summarize",
                router_name=router_name,
                entries=", ".join(r["dst"] for r in group),
                block=str(block),
                via=via,
                dev=dev
            )
            for route in group:
                route["has_warnings"] = True

from analyzer.prefixes import get_prefixes_for_interface
from parser.l2 import get_node
from utils.warning import add_warning

# -----------------------------------------------------------------
# Infers networks from level 2 nodes, p2p links and their addresses
# -----------------------------------------------------------------

def infer_networks(data):
    net_counter = 1
    data["networks"] = {}

    # -----------------------------------------
    # 1. REAL NETWORKS (switch / wifi)
    # -----------------------------------------
    for nid, l2 in data.get("l2nodes", {}).items():

        members = []
        member_ifaces = []

        for link in data["links"]:
            if link["node1"] == nid:
                node = get_node(data, link["node2"])
                members.append(node["name"])
                member_ifaces.append((link["node2"], link["iface2"]))

            elif link["node2"] == nid:
                node = get_node(data, link["node1"])
                members.append(node["name"])
                member_ifaces.append((link["node1"], link["iface1"]))

        net = {
            "id": net_counter,
            "name": l2["name"],
            "kind": "wireless" if "WIRELESS" in l2["type"] else "lan",
            "members": members,
            "prefixes": set()
        }

        # collect prefixes from all router interfaces in this network
        for node_id, iface in member_ifaces:
            node = get_node(data, node_id)

            if node.get("type") != "router":
                continue

            prefixes = get_prefixes_for_interface(node_id, iface, data)

            if not prefixes:
                add_warning(
                    data,
                    f"{node['name']} no tiene una dirección IP en {iface['name']} (red {l2['name']})",
                    wtype="missing",
                    scope="interface",
                    network=l2["name"],
                    node=node["name"],
                    interface=iface["name"],
                    code="missing_ip_interface"
                )

            net["prefixes"].update(prefixes)

        net["prefixes"] = sorted(list(net["prefixes"])) if net["prefixes"] else ["-"]

        data["networks"][net_counter] = net
        net_counter += 1

    # -----------------------------------------
    # 2. P2P NETWORKS (router-router only)
    # -----------------------------------------
    for link in data["links"]:
        n1 = get_node(data, link["node1"])
        n2 = get_node(data, link["node2"])

        if n1.get("type") != "router" or n2.get("type") != "router":
            continue

        # skip if already part of an L2 network
        if link["node1"] in data.get("l2nodes", {}) or link["node2"] in data.get("l2nodes", {}):
            continue

        net = {
            "id": net_counter,
            "name": f"{n1['name']}<>{n2['name']}",
            "kind": "point-to-point",
            "members": [n1["name"], n2["name"]],
            "member_interfaces": [
                {"node": link["node1"], "iface": link["iface1"]["name"]},
                {"node": link["node2"], "iface": link["iface2"]["name"]}
            ],
            "prefixes": set()
        }

        p1 = get_prefixes_for_interface(link["node1"], link["iface1"], data)
        p2 = get_prefixes_for_interface(link["node2"], link["iface2"], data)

        net["prefixes"].update(p1)
        net["prefixes"].update(p2)

        if not p1:
            add_warning(
                data,
                f"{n1['name']} no tiene una dirección IP en {link['iface1']['name']} (p2p)",
                wtype="missing",
                scope="interface",
                network=f"{n1['name']}<>{n2['name']}",
                node=n1["name"],
                interface=link["iface1"]["name"],
                code="missing_ip_p2p"
            )

        if not p2:
            add_warning(
                data,
                f"{n2['name']} no tiene una dirección IP en {link['iface2']['name']} (p2p)",
                wtype="missing",
                scope="interface",
                network=f"{n1['name']}<>{n2['name']}",
                node=n2["name"],
                interface=link["iface2"]["name"],
                code="missing_ip_p2p"
            )

        net["prefixes"] = sorted(list(net["prefixes"])) if net["prefixes"] else ["-"]

        data["networks"][net_counter] = net
        net_counter += 1

    data["networks"] = dict(sorted(data["networks"].items(), key=lambda item: item[1]["prefixes"]))

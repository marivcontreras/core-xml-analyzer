def parse_l2_networks(root, data):
    nets = root.find("networks")
    if nets is None:
        return

    data["l2nodes"] = {}

    for net in nets.findall("network"):
        nid = net.get("id")
        name = net.get("name")
        ntype = net.get("type")

        data["l2nodes"][nid] = {
            "id": nid,
            "name": name,
            "type": ntype
        }


def get_node(data, node_id):
    if node_id in data["devices"]:
        return data["devices"][node_id]

    if node_id in data.get("l2nodes", {}):
        return data["l2nodes"][node_id]

    return {"id": node_id, "name": f"node{node_id}", "type": "unknown"}

import re

INTRANET_ROUTERS = {"R1-DC", "R2", "R3", "R4", "R5", "R6"}

def is_intranet_router(router):
    return router in INTRANET_ROUTERS

# ----------------------------------------------------------
# Infers devices/nodes from devices section (level 3 nodes)
# ----------------------------------------------------------
def parse_devices(root, data):
    devices = root.find("devices")
    if devices is None:
        return

    for dev in devices.findall("device"):
        dev_id = dev.get("id")
        name = dev.get("name")
        dtype = dev.get("type")

        item = {
            "id": dev_id,
            "name": name,
            "type": dtype
        }

        data["devices"][dev_id] = item
        data["nodes"][dev_id] = item
        
        if dtype == "router":
            data["routers"][dev_id] = item

# ---------------------------------------------------------
# Infers devices/nodes from networks section (level 2 nodes)
# ---------------------------------------------------------
def parse_network_nodes(root, data):
    section = root.find("networks")
    if section is None:
        return

    for net in section.findall("network"):
        nid = net.get("id")
        item = {
            "id": nid,
            "name": net.get("name"),
            "type": net.get("type")
        }

        data["nodes"][nid] = item

# --------------------------------------------
# Parses networks from network section
# --------------------------------------------
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

# --------------------------------------------
# Gets a node either from l3nodes or l2nodes
# --------------------------------------------
def get_node(data, node_id):
    if node_id in data["devices"]:
        return data["devices"][node_id]

    if node_id in data.get("l2nodes", {}):
        return data["l2nodes"][node_id]

    return {"id": node_id, "name": f"node{node_id}", "type": "unknown"}

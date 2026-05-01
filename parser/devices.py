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
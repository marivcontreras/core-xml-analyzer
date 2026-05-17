# --------------------------------------------
# Parses links from links section
# --------------------------------------------
def parse_links(root, data):
    links = root.find("links")
    if links is None:
        return

    for link in links.findall("link"):
        node1 = link.get("node1")
        node2 = link.get("node2")

        iface1 = link.find("iface1")
        iface2 = link.find("iface2")

        lnk = {
            "node1": node1,
            "node2": node2,
            "iface1": iface_to_dict(iface1),
            "iface2": iface_to_dict(iface2) if iface2 is not None else None
        }

        data["links"].append(lnk)

# --------------------------------------------
# Parse interface from link
# --------------------------------------------
def iface_to_dict(iface):
    if iface is None:
        return None

    return {
        "id": iface.get("id"),
        "name": iface.get("name"),
        "ip4": iface.get("ip4"),
        "ip4_mask": iface.get("ip4_mask"),
        "ip6": iface.get("ip6"),
        "ip6_mask": iface.get("ip6_mask")
    }


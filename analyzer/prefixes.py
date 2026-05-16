import ipaddress
import re

# ----------------------------------------------------------
# Obtains net prefixes for a given node interface:
# looks up static route and radvd first,
# then defaults to visually configurated ones if none present.
# ----------------------------------------------------------
def get_prefixes_for_interface(node_id, iface, data):
    if not iface:
        return set()

    iface_name = iface.get("name")
    prefixes = set()

    # 1. StaticRoute
    prefixes.update(get_prefixes_from_staticroute(node_id, iface_name, data))

    # 2. RADVD
    prefixes.update(get_radvd_interfaces(data, node_id, iface_name))

    # 3. Fallback (only if nothing found)
    if not prefixes:
        prefixes.update(get_prefixes_from_link_iface(iface))

    return prefixes

# ----------------------------------------------------------------------------
# Gets prefixes for a given node interface from static route ip addr commands
# ----------------------------------------------------------------------------
def get_prefixes_from_staticroute(node_id, iface_name, data):
    prefixes = set()
    services = data["services"].get(node_id, {})
    text = services.get("StaticRoute", "")

    matches = re.findall(
        r'ip\s+-6\s+addr\s+add\s+([0-9a-fA-F:]+)/(\d+)\s+dev\s+(\S+)',
        text
    )

    for addr, mask, dev in matches:
        if dev != iface_name:
            continue

        try:
            net = ipaddress.ip_network(f"{addr}/{mask}", strict=False)
            prefixes.add(str(net))
        except:
            pass

    return prefixes

# ------------------------------------------------------------------------------
# Gets prefixes configurated for a given router interface/s from radvd configuration
# ------------------------------------------------------------------------------
def get_radvd_interfaces(data, node_id, iface_name=None):
    result = {}

    services = data["services"].get(node_id, {})
    text = services.get("radvd", "")

    iface_blocks = re.findall(
        r'interface\s+(\S+)\s*\{((?:[^{}]|\{[^{}]*\})*)\}',
        text,
        re.DOTALL
    )

    for iface, body in iface_blocks:
        if iface_name != None and iface != iface_name:
            continue

        prefixes = set()

        matches = re.findall(
            r'prefix\s+([0-9a-fA-F:]+)/(\d+)',
            body
        )

        for addr, mask in matches:
            try:
                net = ipaddress.ip_network(f"{addr}/{mask}", strict=False)
                prefixes.append(net)
            except:
                pass

        if iface_name == None and prefixes:
            result[iface] = prefixes
        elif iface_name != None:
            result = prefixes

    return result

# ----------------------------------------------------------------------------
# Gets prefixes for a given interface xml element
# ----------------------------------------------------------------------------
def get_prefixes_from_link_iface(iface):
    prefixes = set()

    if not iface:
        return prefixes

    try:
        if iface.get("ip4") and iface.get("ip4_mask"):
            net = ipaddress.ip_network(
                f"{iface['ip4']}/{iface['ip4_mask']}",
                strict=False
            )
            prefixes.add(str(net))
    except:
        pass

    try:
        if iface.get("ip6") and iface.get("ip6_mask"):
            net = ipaddress.ip_network(
                f"{iface['ip6']}/{iface['ip6_mask']}",
                strict=False
            )
            prefixes.add(str(net))
    except:
        pass

    return prefixes

# ----------------------------------------------------------------------------
# Gets IP address for a given node interface from static route ip addr commands
# ----------------------------------------------------------------------------
def get_staticroute_interface_addresses(data, node_id, iface_name = None):
    services = data["services"].get(node_id, {})
    text = services.get("StaticRoute", "")

    matches = re.findall(
        r'ip\s+-6\s+addr\s+add\s+([0-9a-fA-F:]+)\s*/\s*(\d+)\s+dev\s+([a-zA-Z0-9_.-]+)',
        text
    )

    #data["warnings"].append(f"node {node_id} for {iface_name}: found {matches} IP addresses")
    result = []

    for addr, mask, dev in matches:
        if iface_name == None or dev == iface_name:
            try:
                ip = ipaddress.ip_interface(f"{addr}/{mask}")
                result.append(ip)
            except:
                pass

    return result


import ipaddress
import re

from parser.devices import get_node

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

    # IPv6 pattern: ip -6 addr add <ipv6>/<mask> dev <dev>
    ipv6_matches = re.findall(
        r'ip\s+-6\s+addr\s+add\s+([0-9a-fA-F:]+)/(\d+)\s+dev\s+(\S+)',
        text
    )
    
    # IPv4 pattern: ip addr add <ipv4>/<mask> dev <dev> or ip -4 addr add ...
    ipv4_matches = re.findall(
        r'ip\s+(?:-4\s+)?addr\s+add\s+([0-9.]+)/(\d+)\s+dev\s+(\S+)',
        text
    )
    
    # Combine both patterns
    all_matches = ipv6_matches + ipv4_matches

    for addr, mask, dev in all_matches:
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

    result = []
    seen = set()

    # IPv6 pattern: ip -6 addr add <ipv6>/<mask> dev <dev>
    ipv6_matches = re.findall(
        r'ip\s+-6\s+addr\s+add\s+([0-9a-fA-F:]+)\s*/\s*(\d+)\s+dev\s+([a-zA-Z0-9_.-]+)',
        text
    )
    
    # IPv4 pattern: ip addr add <ipv4>/<mask> dev <dev> or ip -4 addr add ...
    ipv4_matches = re.findall(
        r'ip\s+(?:-4\s+)?addr\s+add\s+([0-9.]+)\s*/\s*(\d+)\s+dev\s+([a-zA-Z0-9_.-]+)',
        text
    )
    
    # Combine both patterns
    all_matches = ipv6_matches + ipv4_matches

    for addr, mask, dev in all_matches:
        if iface_name == None or dev == iface_name:
            try:
                ip = ipaddress.ip_interface(f"{addr}/{mask}")
                if ip not in seen:
                    result.append(ip)
                    seen.add(ip)

            except:
                pass
    
    # ------------------------------------------------------------
    # Recover from parsed links
    # ------------------------------------------------------------

    for link in data.get("links", []):

        candidates = [
            (link.get("node1"), link.get("iface1")),
            (link.get("node2"), link.get("iface2"))
        ]

        for candidate_node_id, iface in candidates:

            if iface is None:
                continue

            if candidate_node_id != node_id:
                continue

            dev = iface.get("name")

            if iface_name is not None and dev != iface_name:
                continue

            for field in ["ip4", "ip6"]:

                addr = iface.get(field)
                mask = iface.get(f"{field}_mask")
                if not addr:
                    continue

                try:
                    ip = ipaddress.ip_interface(f"{addr}/{mask}")

                    if ip not in seen:
                        result.append(ip)
                        seen.add(ip)

                except:
                    pass

    return result


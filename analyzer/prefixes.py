
import ipaddress
import re


def get_prefixes_for_interface(node_id, iface, data):
    if not iface:
        return set()

    iface_name = iface.get("name")
    prefixes = set()

    # 1. StaticRoute
    prefixes.update(get_prefixes_from_staticroute(node_id, iface_name, data))

    # 2. RADVD
    prefixes.update(get_prefixes_from_radvd(node_id, iface_name, data))

    # 3. Fallback (only if nothing found)
    if not prefixes:
        prefixes.update(get_prefixes_from_link_iface(iface))

    return prefixes


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

def get_prefixes_from_radvd(node_id, iface_name, data):
    prefixes = set()
    services = data["services"].get(node_id, {})
    text = services.get("radvd", "")

    # Match full interface blocks (including inner braces)
    
    iface_blocks = re.findall(
        r'interface\s+(\S+)\s*\{((?:[^{}]|\{[^{}]*\})*)\}',
        text,
        re.DOTALL
    )

    for iface, body in iface_blocks:
        if iface != iface_name:
            continue

        matches = re.findall(
            r'prefix\s+([0-9a-fA-F:]+)/(\d+)',
            body
        )       

        for addr, mask in matches:
            try:
                net = ipaddress.ip_network(f"{addr}/{mask}", strict=False)
                prefixes.add(str(net))
            except:
                pass

    return prefixes

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

def get_staticroute_interface_addresses(node_id, iface_name, data):
    services = data["services"].get(node_id, {})
    text = services.get("StaticRoute", "")

    matches = re.findall(
        r'ip\s+-6\s+addr\s+add\s+([0-9a-fA-F:]+)\s*/\s*(\d+)\s+dev\s+([a-zA-Z0-9_.-]+)',
        text
    )

    #data["warnings"].append(f"node {node_id} for {iface_name}: found {matches} IP addresses")
    result = []

    for addr, mask, dev in matches:
        if dev == iface_name:
            try:
                ip = ipaddress.ip_interface(f"{addr}/{mask}")
                result.append(ip)
            except:
                pass

    return result

def get_radvd_interfaces(node_id, data):
    result = {}

    services = data["services"].get(node_id, {})
    text = services.get("radvd", "")

    iface_blocks = re.findall(
        r'interface\s+(\S+)\s*\{((?:[^{}]|\{[^{}]*\})*)\}',
        text,
        re.DOTALL
    )

    for iface, body in iface_blocks:
        prefixes = []

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

        if prefixes:
            result[iface] = prefixes

    return result

def get_staticroute_addresses(node_id, data):
    result = {}

    services = data["services"].get(node_id, {})
    text = services.get("StaticRoute", "")

    matches = re.findall(
        r'ip\s+-6\s+addr\s+add\s+([0-9a-fA-F:]+)/(\d+)\s+dev\s+(\S+)',
        text
    )

    for addr, mask, iface in matches:
        try:
            ip = ipaddress.ip_interface(f"{addr}/{mask}")
        except:
            continue

        if iface not in result:
            result[iface] = []

        result[iface].append(ip)

    return result

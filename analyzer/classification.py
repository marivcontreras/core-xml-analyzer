import ipaddress

def classify_prefix(prefix):
    net = ipaddress.ip_network(prefix, strict=False)

    if net.version == 6:
        if net.network_address.exploded.startswith("fd"):
            return "ipv6-site"
        
        if net.network_address.exploded.startswith("2001"):
            return "ipv6-global"
    if net.version == 4:
        return "ipv4"
    
    return "unknown"

def classify_prefix_type(dst):

    if not dst:
        return "unknown"

    dst = dst.lower()

    if dst in ["default", "::/0"]:
        return "default"

    if dst.startswith("fd"):
        return "site"

    if dst.startswith("2001:"):
        return "global"

    return "other"

def classify_ipv6(ip):
    addr = ip.ip.exploded.lower()

    if addr.startswith("fd"):
        return "site"
    if addr.startswith("20") or addr.startswith("30"):
        return "global"
    return "other"
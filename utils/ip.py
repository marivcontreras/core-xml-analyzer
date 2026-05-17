
import ipaddress

def same_block(p1, p2):
    n1 = ipaddress.ip_network(p1, strict=False)
    n2 = ipaddress.ip_network(p2, strict=False)

    return n1.network_address == n2.network_address and n1.prefixlen == n2.prefixlen

# ----------------------------------------------------------
# Prefix classification: default, site, global, ipv4, other
# ----------------------------------------------------------
def classify_prefix_type(ip):
    dst = ipaddress.ip_network(ip, strict=False)
    if not ip or not dst:
        return "unknown"

    if dst.version == 4:
        return "ipv4"
    
    dst = dst.exploded.lower()

    if dst in ["default", "::/0"]:
        return "default"

    if dst.startswith("fd"):
        return "site"

    if dst.startswith("2001:"):
        return "global" 

    return "other"
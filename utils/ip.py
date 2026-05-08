
import ipaddress

def same_block(p1, p2):
    n1 = ipaddress.ip_network(p1, strict=False)
    n2 = ipaddress.ip_network(p2, strict=False)

    return n1.network_address == n2.network_address and n1.prefixlen == n2.prefixlen

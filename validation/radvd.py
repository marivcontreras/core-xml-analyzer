import ipaddress

from analyzer.prefixes import get_radvd_interfaces, get_staticroute_interface_addresses
from utils.warning import add_warning


def _ip_in_any_prefix(ip, prefixes):
    """True if ip (an ip_interface) falls inside any of the given prefixes.

    Prefixes may be strings ("2001::/64") or ip_network objects; addresses of a
    different family than a prefix are simply skipped for that prefix.
    """
    for prefix in prefixes:
        try:
            net = prefix if isinstance(prefix, (ipaddress.IPv4Network, ipaddress.IPv6Network)) \
                else ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue
        if ip.ip.version != net.version:
            continue
        if ip.ip in net:
            return True
    return False

# -------------------------------------------------------------
# Creates a list of warnings related to radvd configuration issues, such as:
# - Missing IP addresses for configured interfaces
# - Router IP addresses outside of announced prefixes
# -------------------------------------------------------------
def validate_radvd_interfaces(data):
    for node_id, services in data["services"].items():
        if "radvd" not in services:
            continue

        node = data["devices"].get(node_id, {"name": f"node{node_id}"})
        node_name = node["name"]

        radvd_map = get_radvd_interfaces(data, node_id)
        addr_map = get_staticroute_interface_addresses(data, node_id)
       
        for iface, prefixes in radvd_map.items():
            assigned_ips = addr_map.get(iface, [])

            if not assigned_ips:
                add_warning(
                    data,
                    "radvd_without_ip",
                    node=node_name,
                    interface=iface,
                    node_name=node_name,
                    interface_name=iface
                )
                continue

            for ip in assigned_ips:
                if not _ip_in_any_prefix(ip, prefixes):
                    add_warning(
                        data,
                        "ip_outside_radvd_prefix",
                        node=node_name,
                        interface=iface,
                        node_name=node_name,
                        interface_name=iface,
                        ip=ip
                    )

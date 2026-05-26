
from analyzer.prefixes import get_radvd_interfaces, get_staticroute_interface_addresses
from utils.warning import add_warning

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
                if not any(ip.ip in prefix for prefix in prefixes):
                    add_warning(
                        data,
                        "ip_outside_radvd_prefix",
                        node=node_name,
                        interface=iface,
                        node_name=node_name,
                        interface_name=iface,
                        ip=ip
                    )

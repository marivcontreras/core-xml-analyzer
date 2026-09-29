import ipaddress

from utils.warning import add_warning
from validation.configs.ip_commands_config import (
    IPV4_CMD_REGEX,
    IPV4_PREFIX_LENGTH_MIN,
    IPV4_PREFIX_LENGTH_MAX,
    IPV6_CMD_REGEX,
    IPV6_PREFIX_LENGTH_MIN,
    IPV6_PREFIX_LENGTH_MAX,
)

def validate_ip_addr_commands(node_id, data):
    services = data["services"].get(node_id, {})
    text = services.get("StaticRoute", "")

    node = data["devices"].get(node_id, {"name": f"node{node_id}"})
    node_name = node["name"]
    ifaces_with_cmd = set()

    for line_num, line in enumerate(text.splitlines(), start=1):
        line = line.strip()

        if line.startswith("ip -6 addr"):
            cmd_type = "ipv6"
            regex = IPV6_CMD_REGEX
        elif line.startswith("ip addr add") or line.startswith("ip -4 addr add"):
            cmd_type = "ipv4"
            regex = IPV4_CMD_REGEX
        else:
            continue

        match = regex.match(line)

        # ❌ Syntax error
        if not match:
            add_warning(
                data,
                "invalid_ip_command",
                node=node_name,
                node_name=node_name,
                line=line,
                details={"line": line, "line_number": line_num}
            )
            continue

        addr, mask, iface = match.groups()
        ifaces_with_cmd.add(iface)

        if not interface_exists(node_id, iface, data):
            add_warning(
                data,
                "interface_not_found",
                node=node_name,
                interface=iface,
                node_name=node_name,
                interface_name=iface
            )

        # ❌ Invalid prefix length
        try:
            mask_int = int(mask)
            if cmd_type == "ipv4":
                if mask_int < IPV4_PREFIX_LENGTH_MIN or mask_int > IPV4_PREFIX_LENGTH_MAX:
                    raise ValueError()
            else:
                if mask_int < IPV6_PREFIX_LENGTH_MIN or mask_int > IPV6_PREFIX_LENGTH_MAX:
                    raise ValueError()
        except Exception:
            add_warning(
                data,
                "invalid_prefix_length_ipv4" if cmd_type == "ipv4" else "invalid_prefix_length_ipv6",
                node=node_name,
                interface=iface,
                node_name=node_name,
                interface_name=iface,
                line=line
            )
            continue

        # ❌ Invalid IP address
        try:
            if cmd_type == "ipv4":
                ipaddress.IPv4Interface(f"{addr}/{mask}")

            else:
                ipaddress.IPv6Interface(f"{addr}/{mask}")
        except Exception:
            add_warning(
                data,
                "invalid_ipv4" if cmd_type == "ipv4" else "invalid_ipv6",
                node=node_name,
                interface=iface,
                node_name=node_name,
                interface_name=iface,
                line=line
            )
            # Address is malformed: report it and skip the checks below that
            # would otherwise re-parse it and raise.
            continue
        
        if cmd_type == "ipv4":
            ip = ipaddress.ip_interface(f"{addr}/{mask}")
            net = ipaddress.ip_network(f"{addr}/{mask}", strict=False)
            if ip.ip == net.network_address:
                add_warning(
                            data,
                            "net_ip_assigned",
                            node=node_name,
                            node_name=node_name,
                            line=line
                        )
        
    if node.get("type") == "router":
        check_missing_ip_commands(node_id, node_name, ifaces_with_cmd, data)


# -------------------------------------------------------------
# For each interface of a router, warns if it has no ip addr command,
# reporting whether an IP is defined on the link instead.
# -------------------------------------------------------------
def check_missing_ip_commands(node_id, node_name, ifaces_with_cmd, data):
    for link in data["links"]:
        for node_key, iface_key in (("node1", "iface1"), ("node2", "iface2")):
            iface = link.get(iface_key)
            if link[node_key] != node_id or not iface or not iface.get("name"):
                continue

            iface_name = iface["name"]
            if iface_name in ifaces_with_cmd:
                continue

            link_ips = [
                f"{iface[ip_key]}/{iface[mask_key]}" if iface.get(mask_key) else iface[ip_key]
                for ip_key, mask_key in (("ip4", "ip4_mask"), ("ip6", "ip6_mask"))
                if iface.get(ip_key)
            ]
            link_info = (
                f"IP definida en el link: {', '.join(link_ips)}"
                if link_ips else "sin IP definida en el link"
            )

            add_warning(
                data,
                "missing_ip_command",
                node=node_name,
                interface=iface_name,
                node_name=node_name,
                interface_name=iface_name,
                link_info=link_info,
                details={"link_ips": link_ips}
            )


# -------------------------------------------------------------
# Checks if an interface name exists for a given node in the data structure.
# -------------------------------------------------------------
def interface_exists(node_id, iface, data):
    for link in data["links"]:
        if link["node1"] == node_id and link["iface1"] and link["iface1"]["name"] == iface:
            return True
        if link["node2"] == node_id and link["iface2"] and link["iface2"]["name"] == iface:
            return True
    return False
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
       
# -------------------------------------------------------------
# Checks if a network name corresponds to an intranet network
# -------------------------------------------------------------
def interface_exists(node_id, iface, data):
    for link in data["links"]:
        if link["node1"] == node_id and link["iface1"] and link["iface1"]["name"] == iface:
            return True
        if link["node2"] == node_id and link["iface2"] and link["iface2"]["name"] == iface:
            return True
    return False
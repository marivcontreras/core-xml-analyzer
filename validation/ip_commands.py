import re
import ipaddress

from utils.warning import add_warning

IPV6_CMD_REGEX = re.compile(
    r'^\s*ip\s+-6\s+addr\s+add\s+([0-9a-fA-F:]+)/(\d+)\s+dev\s+([a-zA-Z0-9_.-]+)\s*$'
)

def validate_ip_addr_commands(node_id, data):
    services = data["services"].get(node_id, {})
    text = services.get("StaticRoute", "")

    node = data["devices"].get(node_id, {"name": f"node{node_id}"})
    node_name = node["name"]

    for line_num, line in enumerate(text.splitlines(), start=1):
        line = line.strip()

        if not line.startswith("ip -6 addr"):
            continue

        match = IPV6_CMD_REGEX.match(line)
        
        # ❌ Syntax error
        if not match:
            add_warning(
                data,
                f"{node_name}: comando inválido → '{line}'",
                wtype="syntax",
                scope="node",
                node=node_name,
                code="invalid_ip_command",
                details={"line": line, "line_number": line_num}
            )
            continue

        addr, mask, iface = match.groups()

        if not interface_exists(node_id, iface, data):
            add_warning(
                data,
                f"{node_name}: interfaz {iface} no existe",
                wtype="invalid",
                scope="interface",
                node=node_name,
                interface=iface,
                code="interface_not_found"
            )

        # ❌ Invalid prefix length
        try:
            mask_int = int(mask)
            if mask_int < 0 or mask_int > 128:
                raise ValueError()
        except:
            add_warning(
                data,
                f"{node_name}: máscara inválida en '{line}'",
                wtype="invalid",
                scope="interface",
                node=node_name,
                interface=iface,
                code="invalid_prefix_length"
            )
            continue

        # ❌ Invalid IPv6 address
        try:
            ipaddress.IPv6Interface(f"{addr}/{mask}")
        except Exception:
            add_warning(
                data,
                f"{node_name}: dirección IPv6 inválida en '{line}'",
                wtype="invalid",
                scope="interface",
                node=node_name,
                interface=iface,
                code="invalid_ipv6"
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
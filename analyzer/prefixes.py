import ipaddress
import re

from parser.devices import get_node
from report.formatters import reverse_network_name
from utils import config_helper
from utils.subjects import Subject
from validation.configs.ip_commands_config import (
    IPV4_CMD_EXTRACT_REGEX,
    IPV6_CMD_EXTRACT_REGEX,
)

PREFIX_SOURCE_COMMANDS = "ip addr command"
PREFIX_SOURCE_RADVD = "radvd"
PREFIX_SOURCE_LINK = "interfaz core"


def _add_prefix_source(prefixes, prefix, source):
    if prefix not in prefixes:
        prefixes[prefix] = []

    if source not in prefixes[prefix]:
        prefixes[prefix].append(source)


def merge_prefix_sources(*source_maps):
    merged = {}

    for source_map in source_maps:
        if not source_map:
            continue

        for prefix, sources in source_map.items():
            if not isinstance(sources, list):
                sources = [sources]

            for source in sources:
                _add_prefix_source(merged, prefix, source)

    return merged


# ----------------------------------------------------------
# Obtains net prefixes for a given node interface:
# looks up static route and radvd first,
# then defaults to visually configurated ones if none present.
# ----------------------------------------------------------
def get_prefixes_for_interface(node_id, iface, data):
    return set(get_prefixes_for_interface_with_sources(node_id, iface, data).keys())


def get_prefixes_for_interface_with_sources(node_id, iface, data):
    if not iface:
        return {}

    iface_name = iface.get("name")
    prefixes = {}

    # 1. StaticRoute
    for prefix in get_prefixes_from_staticroute(node_id, iface_name, data):
        _add_prefix_source(prefixes, prefix, PREFIX_SOURCE_COMMANDS)

    # 2. RADVD
    if Subject.RADVD in config_helper.get_subjects():
        for prefix in get_radvd_interfaces(data, node_id, iface_name):
            _add_prefix_source(prefixes, prefix, PREFIX_SOURCE_RADVD)

    # 3. Fallback (only if nothing found)
    if not prefixes:
        for prefix in get_prefixes_from_link_iface(iface):
            _add_prefix_source(prefixes, prefix, PREFIX_SOURCE_LINK)

    return prefixes

# ----------------------------------------------------------------------------
# Gets prefixes for a given node interface from static route ip addr commands
# ----------------------------------------------------------------------------
def get_prefixes_from_staticroute(node_id, iface_name, data):
    prefixes = set()
    services = data["services"].get(node_id, {})
    text = services.get("StaticRoute", "")

    ipv6_matches = IPV6_CMD_EXTRACT_REGEX.findall(text)
    ipv4_matches = IPV4_CMD_EXTRACT_REGEX.findall(text)

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
                prefixes.add(str(net))
            except:
                pass

        if iface_name is None and prefixes:
            result[iface] = prefixes
        elif iface_name is not None:
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
def get_staticroute_interface_addresses(data, node_id, iface = None):
    """Collect the IP addresses assigned to a node's interfaces.

    Return shape depends on the ``iface`` argument (mirrors
    ``get_radvd_interfaces``):
      * iface given   -> list of ip_interface for that single interface.
      * iface is None -> dict {interface_name: [ip_interface, ...]} for all
        interfaces of the node.
    """
    iface_name = iface.get("name") if iface else None

    services = data["services"].get(node_id, {})
    text = services.get("StaticRoute", "")

    by_iface = {}
    seen = set()

    def _add(dev, addr, mask):
        try:
            ip = ipaddress.ip_interface(f"{addr}/{mask}")
        except Exception:
            return
        key = (dev, ip)
        if key in seen:
            return
        seen.add(key)
        by_iface.setdefault(dev, []).append(ip)

    ipv6_matches = IPV6_CMD_EXTRACT_REGEX.findall(text)
    ipv4_matches = IPV4_CMD_EXTRACT_REGEX.findall(text)

    for addr, mask, dev in ipv6_matches + ipv4_matches:
        if iface_name is None or dev == iface_name:
            _add(dev, addr, mask)

    # ------------------------------------------------------------
    # Recover from parsed links
    # ------------------------------------------------------------

    for link in data.get("links", []):

        candidates = [
            (link.get("node1"), link.get("iface1")),
            (link.get("node2"), link.get("iface2"))
        ]

        for candidate_node_id, link_iface in candidates:

            if link_iface is None:
                continue

            if candidate_node_id != node_id:
                continue

            dev = link_iface.get("name")

            if iface_name is not None and dev != iface_name:
                continue

            for field in ["ip4", "ip6"]:

                addr = link_iface.get(field)
                mask = link_iface.get(f"{field}_mask")
                if not addr:
                    continue

                _add(dev, addr, mask)

    if iface_name is not None:
        # Single-interface query: preserve the historical flat-list contract.
        return by_iface.get(iface_name, [])

    return by_iface

# -------------------------------------------------------------------
# Returns node and interface information for a given IP address.
# -------------------------------------------------------------------
def resolve_ip_owner(ip_str, data):
    try:
        ip = ipaddress.ip_address(ip_str)
    except:
        print(f"Invalid IP address: {ip_str}")
        return None
    #print(f"Checking for IP {ip_str}...") 
    for net in data["networks"].values():
        for member in net.get("member_interfaces", []):
            node_id = member["node"]
            iface = member["iface"]
            addrs = get_staticroute_interface_addresses(data, node_id, iface)
            #print(f"Found addresses for node {node_id} in {net['name']}, interface {iface}: {addrs}")
            for addr in addrs:
                if addr.ip == ip:
                    node = data["devices"].get(node_id, {"name": f"node{node_id}"})

                    return {
                        "node": node["name"],
                        "interface": iface["name"],
                        "network": net["name"],
                        "type": "neighbor"
                    }

    print(f"IP address {ip_str} not found in any network")
    return {
                "node": None,
                "interface": None,
                "network": None,
                "type": None
            }


def get_network_by_name(data, network_name):
    for net in data["networks"].values():
        if net.get("name") == network_name or net.get("name") == reverse_network_name(network_name):
            return net

    return None

def resolve_route_dev(node_id, via_ip, data):
    if not via_ip:
        return None

    via_info = resolve_ip_owner(via_ip, data)
    #print(f"Resolving route dev for {node_id} with via_info {via_info}")

    network_name = via_info.get("network")

    if not network_name:
        return None
    
    #print(f"Looking for network {network_name} or {reverse_network_name(network_name)} in data")

    network = get_network_by_name(data, network_name)
    
    #print(f"Found network {network_name}: {network}")
    if not network:
        return None

    for member in network.get("member_interfaces", []):

        if member["node"] == node_id:
            #print(f"Found interface {member['iface']} for node {node_id}")
            return member["iface"]["name"]

    return None
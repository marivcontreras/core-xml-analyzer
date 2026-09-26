
import ipaddress

from analyzer.prefixes import get_prefixes_for_interface, get_staticroute_interface_addresses
from utils.ip import PREFIX_TYPE, same_block, classify_prefix_type
from utils import config_helper
from utils.warning import add_warning
from validation.configs.network_config import ADMIN_NETWORK_PATTERN


def resolve_prefix_device(net, prefix, data):
    """Return the device name that contributed the given prefix to a network."""
    #print(f"Resolving device for prefix {prefix} in network {net['name']} with members: {net.get('member_interfaces', [])}")
    for member in net.get("member_interfaces", []):
        node_id = member.get("node")
        iface = member.get("iface")
        iface_name = iface.get("name") if isinstance(iface, dict) else iface

        if not node_id or not iface_name:
            continue

        interface_prefixes = get_prefixes_for_interface(node_id, iface, data)
        print(f"Node {node_id}, Interface {iface_name}: Found prefixes {interface_prefixes}")
        if prefix in interface_prefixes:
            node = data.get("devices", {}).get(node_id, {})
            return node.get("name") or node_id

    return None

# -------------------------------------------------------------
# Creates a list of warnings related to network design and configuration issues, such as:
# - Too many prefixes
# - Wrong prefix length
# - Missing addresses
# -------------------------------------------------------------
def validate_networks(data):
    validate_existing_devices(data)
    used_prefixes = {}

    for net in data["networks"].values():
        prefixes = [p for p in net["prefixes"] if p != "-"]
        #print(f"Validating network {net['name']} with prefixes: {prefixes}")
        if not prefixes:
            continue

        expected_last_octet = config_helper.get_network_last_octet(
            net.get("original_name", net.get("name"))
        )
        
        print(f"Network {net['name']} has expected last octet: {expected_last_octet}")

        if expected_last_octet is not None:
            for prefix in prefixes:
                try:
                    net_obj = ipaddress.ip_network(prefix, strict=False)
                    if net_obj.version == 4:
                        actual_last_octet = int(net_obj.network_address.packed[-1])
                        if actual_last_octet != expected_last_octet:
                            add_warning(
                                data,
                                "invalid_last_octet",
                                network=net["name"],
                                net_name=net["name"],
                                prefix=prefix,
                                expected=expected_last_octet,
                                actual=actual_last_octet,
                                details={
                                    "prefix": prefix,
                                    "expected": expected_last_octet,
                                    "actual": actual_last_octet,
                                }
                            )
                except ValueError:
                    continue

        # ----------------------------------
        # duplicated prefixes across networks
        # ----------------------------------
        for prefix in prefixes:

            if prefix in used_prefixes:

                add_warning(
                    data,
                    "duplicated_prefix",
                    network=net["name"],
                    net_name=net["name"],
                    prefix=prefix,
                    other_network=used_prefixes[prefix],
                    details={
                        "prefix": prefix,
                        "other_network": used_prefixes[prefix]
                    }
                )

            else:
                used_prefixes[prefix] = net["name"]

            # ----------------------------------
            # Wrong mask
            # ----------------------------------

            net_obj = ipaddress.ip_network(prefix, strict=False)
            expected_mask = config_helper.get_network_mask(
                net.get("original_name", net["name"])
            )

            #print(f"Checking network {net['name']} with prefix {prefix}. Expected mask: {expected_mask}, actual mask: {net_obj.prefixlen}")
            
            if expected_mask is not None and net_obj.prefixlen != int(expected_mask):
                device = resolve_prefix_device(net, prefix, data)
                print(f"Network {net['name']} has prefix {prefix} with wrong mask. Expected: /{expected_mask}, actual: /{net_obj.prefixlen}. Device: {device}")
                add_warning(
                    data,
                    "invalid_prefix_length",
                    network=net["name"],
                    net_name=net["name"],
                    prefix=prefix,
                    expected=expected_mask,
                    device=device,
                    details={"prefix": prefix, "expected": expected_mask, "device": device}
                )

        kinds = [classify_prefix_type(p) for p in prefixes]

        if PREFIX_TYPE["unknown"] in kinds:
            add_warning(
                data,
                "invalid_prefixes",
                network=net["name"],
                net_name=net["name"],
                prefixes=', '.join(prefixes),
                details={"prefixes": prefixes}
            )  
              
        # ----------------------------------
        # 1. Too many prefixes
        # ----------------------------------
        if len(prefixes) > config_helper.get_max_prefixes_per_network():
            add_warning(
                data,
                "too_many_prefixes",
                network=net["name"],
                net_name=net["name"],
                prefixes=', '.join(prefixes),
                max_prefixes=config_helper.get_max_prefixes_per_network(),
                details={"prefixes": prefixes}
            )

        if net["kind"] == "point-to-point":
            check_p2p_consistency(net, data)

        if config_helper.get_class_name() == "rdc2":

            if PREFIX_TYPE["ipv4"] in kinds and len(kinds) > 1:
                add_warning(
                    data,
                    "ipv4_with_other_prefixes",
                    network=net["name"],
                    net_name=net["name"],
                    prefixes=', '.join(prefixes),
                    details={"prefixes": prefixes}
                )    

            if PREFIX_TYPE["ipv4"] in kinds and len(kinds) <= 1:
                continue

            # ----------------------------------
            # 3. Missing addresses (global + site)
            # ----------------------------------
            if PREFIX_TYPE["site"] not in kinds:
                add_warning(
                    data,
                    "missing_site_prefix",
                    network=net["name"],
                    net_name=net["name"],
                    existing=', '.join(prefixes),
                    details={"existing": prefixes}
                )

            if ADMIN_NETWORK_PATTERN.lower() not in net["name"].lower():
                if PREFIX_TYPE["global"] not in kinds:
                    add_warning(
                        data,
                        "missing_global_prefix",
                        network=net["name"],
                        net_name=net["name"],
                        existing=', '.join(prefixes),
                        details={"existing": prefixes}
                    )

            # ----------------------------------
            # 4. Admin network should NOT have global
            # (heuristic: name contains configured ADMIN_NETWORK_PATTERN)
            # ----------------------------------
            if ADMIN_NETWORK_PATTERN.lower() in net["name"].lower():
                if PREFIX_TYPE["global"] in kinds:
                    add_warning(
                        data,
                        "admin_with_global",
                        network=net["name"],
                        net_name=net["name"],
                        details={"prefixes": prefixes}
                    )

def validate_existing_devices(data):
    config = config_helper.get_config() or {}
    configured_devices = config.get("devices", {})
    configured_networks = config.get("networks", {})

    device_names = {
        device.get("name")
        for device in data.get("devices", {}).values()
        if device.get("name")
    }

    l2_network_names = {
        config_helper.format_network_name(
            network.get("original_name", network.get("name"))
        )
        for network in data.get("l2nodes", {}).values()
        if network.get("original_name", network.get("name"))
    }

    configured_router_names = [
        router
        for routers in configured_devices.values()
        if isinstance(routers, (list, tuple, set))
        for router in routers
        if router not in device_names
    ]
    
    for router in dict.fromkeys(configured_router_names):
        add_warning(
            data,
            "missing_configured_router",
            node_name=router,
            details={"router": router}
        )

    configured_network_names = [
        network_name
        for networks in configured_networks.values()
        for network_name in config_helper.get_network_names(networks)
        if network_name
        and "<>" not in network_name
        and network_name not in l2_network_names
    ]

    for network_name in dict.fromkeys(configured_network_names):
        print(f"Configured network {network_name} is missing in the XML data.")
        add_warning(
            data,
            "missing_configured_network",
            network=network_name,
            net_name=network_name,
            details={"network": network_name}
        )

# -------------------------------------------------------------
# Creates a list of warnings related to p2p network design and configuration issues, such as:
# - IPv6 addresses of different blocks on the two endpoints
# - Missing addresses
# -------------------------------------------------------------
def check_p2p_consistency(net, data):
    # only applies to p2p
    if net["kind"] != "point-to-point":
        return

    members = net.get("member_interfaces", [])
    if len(members) != 2:
        return
    
    endpoints = []
    class_name = config_helper.get_class_name()

    for m in members:
        node_id = m["node"]
        iface = m["iface"]

        addrs = get_staticroute_interface_addresses(data, node_id, iface)
        print(f"Node {m}, Interface {iface}: Found addresses {addrs}")
        #data["warnings"].append(f"node {node_id} for {iface}: found {addrs} IP addresses")

        ipv4 = None
        global_ip = None
        site_ip = None

        for ip in addrs:
            if ip.version == 4 and not ipv4:
                # levanta primero de static route y segundo de link, si hay una ipv4 en static route uso esa, sino recien ahi agarro la del link
                ipv4 = ip
            elif ip.version == 6:
                if classify_prefix_type(ip) == PREFIX_TYPE["site"]:  # fd00::/8
                    site_ip = ip
                elif classify_prefix_type(ip) == PREFIX_TYPE["global"]:  # 2001::/16
                    global_ip = ip

        endpoints.append({
            "node": node_id,
            "iface": iface,
            "ipv4": ipv4,
            "global": global_ip,
            "site": site_ip
        })

    #data["warnings"].append(f"endpoints {endpoints}")
    if len(endpoints) != 2:
        return

    a, b = endpoints
  
    if a["ipv4"] and b["ipv4"]:
        print(f"Checking IPv4 consistency for network {net['name']}: {a['ipv4']} vs {b['ipv4']}")
        if not same_block(str(a["ipv4"].network), str(b["ipv4"].network)):
            add_warning(
                data,
                "p2p_ipv4_mismatch",
                network=net["name"],
                net_name=net["name"],
                ipv4_a=a["ipv4"],
                ipv4_b=b["ipv4"]
            )

    if (not config_helper.get_ipv6_support()):
        for ep in endpoints:
            if not ep["ipv4"]:
                add_warning(
                    data,
                    "p2p_missing_ipv4",
                    network=net["name"],
                    net_name=net["name"],
                    node_name=data['devices'][ep['node']]['name'],
                    iface=ep['iface'].get("name")
                )

    # --- GLOBAL CHECK ---
    if a["global"] and b["global"]:
        if not same_block(str(a["global"].network), str(b["global"].network)):
            add_warning(
                data,
                "p2p_global_mismatch",
                network=net["name"],
                net_name=net["name"],
                global_a=a["global"],
                global_b=b["global"]
            )

    # --- SITE CHECK ---
    if a["site"] and b["site"]:
        if not same_block(str(a["site"].network), str(b["site"].network)):
            add_warning(
                data,
                "p2p_site_mismatch",
                network=net["name"],
                net_name=net["name"],
                site_a=a["site"],
                site_b=b["site"]
            )

    # --- MISSING ADDRESS CHECK ---
    if(config_helper.is_intranet_network(net["name"])):
        for ep in endpoints:
            if not ep["global"]:
                add_warning(
                    data,
                    "p2p_missing_global",
                    network=net["name"],
                    net_name=net["name"],
                    node_name=data['devices'][ep['node']]['name'],
                    iface=ep['iface'].get("name")
                )

            if not ep["site"]:
                add_warning(
                    data,
                    "p2p_missing_site",
                    network=net["name"],
                    net_name=net["name"],
                    node_name=data['devices'][ep['node']]['name'],
                    iface=ep['iface'].get("name")
                )

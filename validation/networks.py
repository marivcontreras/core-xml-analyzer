
import ipaddress

from analyzer.prefixes import get_staticroute_interface_addresses
from utils.ip import PREFIX_TYPE, same_block, classify_prefix_type
from utils import config_helper
from utils.warning import add_warning
from validation.configs.network_config import ADMIN_NETWORK_PATTERN

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
        print(f"Validating network {net['name']} with prefixes: {prefixes}")
        if not prefixes:
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
            print(f"Checking network {net['name']} with prefix {prefix}. Expected mask: {expected_mask}, actual mask: {net_obj.prefixlen}")
            if expected_mask is not None and net_obj.prefixlen != int(expected_mask):
                add_warning(
                    data,
                    "invalid_prefix_length",
                    network=net["name"],
                    net_name=net["name"],
                    prefix=prefix,
                    expected=expected_mask,
                    details={"prefix": prefix, "expected": expected_mask}
                )

        kinds = [classify_prefix_type(p) for p in prefixes]

        if "unknown" in kinds:
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
        #data["warnings"].append(f"node {node_id} for {iface}: found {addrs} IP addresses")

        ipv4 = None
        global_ip = None
        site_ip = None

        for ip in addrs:
            if class_name == "rdc1" and ip.version == 4:
                ipv4 = ip
            elif ip.version != 6:
                continue
            
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

    if class_name == "rdc1":
        if a["ipv4"] and b["ipv4"]:
            if not same_block(str(a["ipv4"].network), str(b["ipv4"].network)):
                add_warning(
                    data,
                    "p2p_ipv4_mismatch",
                    network=net["name"],
                    net_name=net["name"],
                    ipv4_a=a["ipv4"],
                    ipv4_b=b["ipv4"]
                )

        for ep in endpoints:
            if not ep["ipv4"]:
                add_warning(
                    data,
                    "p2p_missing_ipv4",
                    network=net["name"],
                    net_name=net["name"],
                    node_name=data['devices'][ep['node']]['name'],
                    iface=ep['iface']
                )
        return

    elif class_name == "rdc2":
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
                        iface=ep['iface']
                    )

                if not ep["site"]:
                    add_warning(
                        data,
                        "p2p_missing_site",
                        network=net["name"],
                        net_name=net["name"],
                        node_name=data['devices'][ep['node']]['name'],
                        iface=ep['iface']
                    )

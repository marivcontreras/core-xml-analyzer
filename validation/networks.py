
import ipaddress

from analyzer.prefixes import get_staticroute_interface_addresses
from utils.ip import PREFIX_TYPE, same_block, classify_prefix_type
from utils.warning import add_warning

# -------------------------------------------------------------
# Creates a list of warnings related to network design and configuration issues, such as:
# - Too many prefixes
# - Wrong prefix length
# - Missing addresses
# -------------------------------------------------------------
def validate_networks(data):
    used_prefixes = {}
    for net in data["networks"].values():
        prefixes = [p for p in net["prefixes"] if p != "-"]

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

        kinds = [classify_prefix_type(p) for p in prefixes]

        if PREFIX_TYPE["ipv4"] in kinds and len(kinds) <= 1:
            continue

        if PREFIX_TYPE["ipv4"] in kinds and len(kinds) > 1:
            add_warning(
                data,
                "ipv4_with_other_prefixes",
                network=net["name"],
                net_name=net["name"],
                prefixes=', '.join(prefixes),
                details={"prefixes": prefixes}
            )
        
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
        if len(prefixes) > 2:
            add_warning(
                data,
                "too_many_prefixes",
                network=net["name"],
                net_name=net["name"],
                prefixes=', '.join(prefixes),
                details={"prefixes": prefixes}
            )

        # ----------------------------------
        # 2. Wrong mask
        # ----------------------------------
        for p in prefixes:
            net_obj = ipaddress.ip_network(p, strict=False)

            if net["kind"] in ["lan", "wireless"] and net_obj.prefixlen != 64:
                add_warning(
                    data,
                    "invalid_prefix_length",
                    network=net["name"],
                    net_name=net["name"],
                    prefix=p,
                    expected=64,
                    details={"prefix": p, "expected": 64}
                )

            if net["kind"] == "point-to-point" and net_obj.prefixlen != 127:
                add_warning(
                    data,
                    "invalid_prefix_length",
                    network=net["name"],
                    net_name=net["name"],
                    prefix=p,
                    expected=127,
                    details={"prefix": p, "expected": 127}
                )

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

        if "admin" not in net["name"].lower():  # you may refine later
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
        # (basic heuristic: name contains 'Admin')
        # ----------------------------------
        if "admin" in net["name"].lower():
            if PREFIX_TYPE["global"] in kinds:
                add_warning(
                    data,
                    "admin_with_global",
                    network=net["name"],
                    net_name=net["name"],
                    details={"prefixes": prefixes}
                )

        # ----------------------------------
        # 5. P2P consistency
        # ----------------------------------
        if net["kind"] == "point-to-point":
            check_p2p_consistency(net, data)

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

    for m in members:
        node_id = m["node"]
        iface = m["iface"]

        addrs = get_staticroute_interface_addresses(data, node_id, iface)
        #data["warnings"].append(f"node {node_id} for {iface}: found {addrs} IP addresses")

        global_ip = None
        site_ip = None

        for ip in addrs:
            if ip.version != 6:
                continue
            
            if classify_prefix_type(ip) == PREFIX_TYPE["site"]:  # fd00::/8
                site_ip = ip
            elif classify_prefix_type(ip) == PREFIX_TYPE["global"]:  # 2001::/16
                global_ip = ip

        endpoints.append({
            "node": node_id,
            "iface": iface,
            "global": global_ip,
            "site": site_ip
        })

    #data["warnings"].append(f"endpoints {endpoints}")
    if len(endpoints) != 2:
        return

    a, b = endpoints

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

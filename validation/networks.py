
import ipaddress

from analyzer.prefixes import get_staticroute_interface_addresses
from utils.ip import same_block, classify_prefix_type
from utils.warning import add_warning

# -------------------------------------------------------------
# Creates a list of warnings related to network design and configuration issues, such as:
# - Too many prefixes
# - Wrong prefix length
# - Missing addresses
# -------------------------------------------------------------
def validate_networks(data):
    for net in data["networks"].values():
        prefixes = [p for p in net["prefixes"] if p != "-"]

        if not prefixes:
            continue

        kinds = [classify_prefix_type(p) for p in prefixes]
        
        print(kinds)

        if "ipv4" in kinds and len(kinds) <= 1:
            continue

        if "ipv4" in kinds and len(kinds) > 1:
            add_warning(
                data,
                f"{net['name']}: se asignaron direcciones adicionales en internet ({', '.join(prefixes)})",
                wtype="design",
                scope="network",
                network=net["name"],
                code="ipv4_with_other_prefixes",
                details={"prefixes": prefixes}
            )
        
        if "unknown" in kinds:
            add_warning(
                data,
                f"{net['name']}: prefijo invalido ({', '.join(prefixes)})",
                wtype="design",
                scope="network",
                network=net["name"],
                code="invalid_prefixes",
                details={"prefixes": prefixes}
            )        
        
        # ----------------------------------
        # 1. Too many prefixes
        # ----------------------------------
        if len(prefixes) > 2:
            add_warning(
                data,
                f"{net['name']}: se asignaron mas de 2 bloques de red ({', '.join(prefixes)})",
                wtype="design",
                scope="network",
                network=net["name"],
                code="too_many_prefixes",
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
                    f"{net['name']}: prefijo {p} deberia ser /64",
                    wtype="invalid",
                    scope="network",
                    network=net["name"],
                    code="invalid_prefix_length",
                    details={"prefix": p, "expected": 64}
                )

            if net["kind"] == "point-to-point" and net_obj.prefixlen != 127:
                add_warning(
                    data,
                    f"{net['name']}: prefijo {p} deberia ser /127",
                    wtype="invalid",
                    scope="network",
                    network=net["name"],
                    code="invalid_prefix_length",
                    details={"prefix": p, "expected": 127}
                )

        # ----------------------------------
        # 3. Missing addresses (global + site)
        # ----------------------------------
        if "site" not in kinds:
            add_warning(
                data,
                f"{net['name']}: prefijo site faltante (existentes: {', '.join(prefixes)})",
                wtype="missing",
                scope="network",
                network=net["name"],
                code="missing_site_prefix",
                details={"existing": prefixes}
            )

        if "admin" not in net["name"].lower():  # you may refine later
            if "global" not in kinds:
                add_warning(
                    data,
                    f"{net['name']}: prefijo global faltante (existentes: {', '.join(prefixes)})",
                    wtype="missing",
                    scope="network",
                    network=net["name"],
                    code="missing_global_prefix",
                    details={"existing": prefixes}
                )

        # ----------------------------------
        # 4. Admin network should NOT have global
        # (basic heuristic: name contains 'Admin')
        # ----------------------------------
        if "admin" in net["name"].lower():
            if "global" in kinds:
                add_warning(
                    data,
                    f"{net['name']}: red admin no debería usar direcciones globales",
                    wtype="design",
                    scope="network",
                    network=net["name"],
                    code="admin_with_global",
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
            
            if classify_prefix_type(ip) == "site":  # fd00::/8
                site_ip = ip
            elif classify_prefix_type(ip) == "global":  # 2001::/16
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
                f"{net['name']}: direcciones globales de distintos bloques ({a['global']} - {b['global']})",
                wtype="inconsistent",
                scope="link",
                network=net["name"],
                code="p2p_global_mismatch"
            )
    # --- SITE CHECK ---
    if a["site"] and b["site"]:
        if not same_block(str(a["site"].network), str(b["site"].network)):
            add_warning(
                data,
                f"{net['name']}: direcciones site de distintos bloques ({a['site']} - {b['site']})",
                wtype="inconsistent",
                scope="link",
                network=net["name"],
                code="p2p_site_mismatch"
            )

    # --- MISSING ADDRESS CHECK ---
    for ep in endpoints:
        if not ep["global"]:
            add_warning(
                data,
                f"{net['name']}: {data['devices'][ep['node']]['name']} ({ep['iface']}) sin dirección global",
                wtype="inconsistent",
                scope="link",
                network=net["name"],
                code="p2p_missing_global"
            )

        if not ep["site"]:
            add_warning(
                data,
                f"{net['name']}: {data['devices'][ep['node']]['name']} ({ep['iface']}) sin dirección site", 
                wtype="inconsistent",
                scope="link",
                network=net["name"],
                code="p2p_missing_site"
            )

# parser.py
import re
import ipaddress
import xml.etree.ElementTree as ET


def parse_xml(xml_text):
    root = ET.fromstring(xml_text)

    data = {
        "devices": {},
        "links": [],
        "services": {},
        "routers": {},
        "networks": {},
        "nodes": {},
        "warnings": []
    }

    parse_devices(root, data)
    parse_network_nodes(root, data)
    parse_links(root, data)
    parse_services(root, data)
    parse_l2_networks(root, data)
    infer_networks(data)
    validate_networks(data)
    validate_radvd_interfaces(data)
    
    return data

# --------------------------------------------------
# DEVICES
# --------------------------------------------------

def parse_devices(root, data):
    devices = root.find("devices")
    if devices is None:
        return

    for dev in devices.findall("device"):
        dev_id = dev.get("id")
        name = dev.get("name")
        dtype = dev.get("type")

        item = {
            "id": dev_id,
            "name": name,
            "type": dtype
        }

        data["devices"][dev_id] = item
        data["nodes"][dev_id] = item
        
        if dtype == "router":
            data["routers"][dev_id] = item


def parse_network_nodes(root, data):
    section = root.find("networks")
    if section is None:
        return

    for net in section.findall("network"):
        nid = net.get("id")
        item = {
            "id": nid,
            "name": net.get("name"),
            "type": net.get("type")
        }

        data["nodes"][nid] = item
# -----------------------------------
# ---------------
# LINKS
# --------------------------------------------------

def parse_links(root, data):
    links = root.find("links")
    if links is None:
        return

    for link in links.findall("link"):
        node1 = link.get("node1")
        node2 = link.get("node2")

        iface1 = link.find("iface1")
        iface2 = link.find("iface2")

        lnk = {
            "node1": node1,
            "node2": node2,
            "iface1": iface_to_dict(iface1),
            "iface2": iface_to_dict(iface2) if iface2 is not None else None
        }

        data["links"].append(lnk)


def iface_to_dict(iface):
    if iface is None:
        return None

    return {
        "id": iface.get("id"),
        "name": iface.get("name"),
        "ip4": iface.get("ip4"),
        "ip4_mask": iface.get("ip4_mask"),
        "ip6": iface.get("ip6"),
        "ip6_mask": iface.get("ip6_mask")
    }


# --------------------------------------------------
# SERVICES
# --------------------------------------------------

def parse_services(root, data):
    section = root.find("service_configurations")
    if section is None:
        return

    for svc in section.findall("service"):
        node = svc.get("node")
        name = svc.get("name")

        template = svc.find(".//template")
        text = template.text if template is not None and template.text else ""

        if node not in data["services"]:
            data["services"][node] = {}

        data["services"][node][name] = text


# --------------------------------------------------
# NETWORK INFERENCE
# --------------------------------------------------
def infer_networks(data):
    net_counter = 1
    data["networks"] = {}

    # -----------------------------------------
    # 1. REAL NETWORKS (switch / wifi)
    # -----------------------------------------
    for nid, l2 in data.get("l2nodes", {}).items():

        members = []
        member_ifaces = []

        for link in data["links"]:
            if link["node1"] == nid:
                node = get_node(data, link["node2"])
                members.append(node["name"])
                member_ifaces.append((link["node2"], link["iface2"]))

            elif link["node2"] == nid:
                node = get_node(data, link["node1"])
                members.append(node["name"])
                member_ifaces.append((link["node1"], link["iface1"]))

        net = {
            "id": net_counter,
            "name": l2["name"],
            "kind": "wireless" if "WIRELESS" in l2["type"] else "lan",
            "members": members,
            "prefixes": set()
        }

        # collect prefixes from all router interfaces in this network
        for node_id, iface in member_ifaces:
            node = get_node(data, node_id)

            if node.get("type") != "router":
                continue

            prefixes = get_prefixes_for_interface(node_id, iface, data)

            if not prefixes:
                data["warnings"].append(
                    f"{node['name']} has no IP config on {iface['name']} (network {l2['name']})"
                )

            net["prefixes"].update(prefixes)

        net["prefixes"] = sorted(list(net["prefixes"])) if net["prefixes"] else ["-"]

        data["networks"][net_counter] = net
        net_counter += 1

    # -----------------------------------------
    # 2. P2P NETWORKS (router-router only)
    # -----------------------------------------
    for link in data["links"]:
        n1 = get_node(data, link["node1"])
        n2 = get_node(data, link["node2"])

        if n1.get("type") != "router" or n2.get("type") != "router":
            continue

        # skip if already part of an L2 network
        if link["node1"] in data.get("l2nodes", {}) or link["node2"] in data.get("l2nodes", {}):
            continue

        net = {
            "id": net_counter,
            "name": f"{n1['name']} <-> {n2['name']}",
            "kind": "point-to-point",
            "members": [n1["name"], n2["name"]],
            "member_interfaces": [
                {"node": link["node1"], "iface": link["iface1"]["name"]},
                {"node": link["node2"], "iface": link["iface2"]["name"]}
            ],
            "prefixes": set()
        }

        p1 = get_prefixes_for_interface(link["node1"], link["iface1"], data)
        p2 = get_prefixes_for_interface(link["node2"], link["iface2"], data)

        net["prefixes"].update(p1)
        net["prefixes"].update(p2)

        if not p1:
            data["warnings"].append(
                f"{n1['name']} missing IP config on {link['iface1']['name']} (p2p)"
            )

        if not p2:
            data["warnings"].append(
                f"{n2['name']} missing IP config on {link['iface2']['name']} (p2p)"
            )

        net["prefixes"] = sorted(list(net["prefixes"])) if net["prefixes"] else ["-"]

        data["networks"][net_counter] = net
        net_counter += 1

    data["networks"] = dict(sorted(data["networks"].items(), key=lambda item: item[1]["prefixes"]))

# --------------------------------------------------
# NETWORK VALIDATION
# --------------------------------------------------

def validate_networks(data):
    for net in data["networks"].values():
        prefixes = [p for p in net["prefixes"] if p != "-"]

        if not prefixes:
            continue

        kinds = [classify_prefix(p) for p in prefixes]
        
        if "ipv4" in kinds and len(kinds) <= 1:
            continue

        if "ipv4" in kinds and len(kinds) > 1:
            data["warnings"].append(
                f"{net['name']}: se asignaron direcciones adicionales en internet ({', '.join(prefixes)})"
            )
        
        if "unknown" in kinds:
            data["warnings"].append(
                f"{net['name']}: prefijo desconocido ({', '.join(prefixes)})"
            )

        
        
        # ----------------------------------
        # 1. Too many prefixes
        # ----------------------------------
        if len(prefixes) > 2:
            data["warnings"].append(
                f"{net['name']}: se asignaron mas de 2 bloques de red ({', '.join(prefixes)})"
            )

        # ----------------------------------
        # 2. Wrong mask
        # ----------------------------------
        for p in prefixes:
            net_obj = ipaddress.ip_network(p, strict=False)

            if net["kind"] in ["lan", "wireless"] and net_obj.prefixlen != 64:
                data["warnings"].append(
                    f"{net['name']}: prefijo {p} deberia ser /64"
                )

            if net["kind"] == "point-to-point" and net_obj.prefixlen != 127:
                data["warnings"].append(
                    f"{net['name']}: prefijo {p} deberia ser /127"
                )

        # ----------------------------------
        # 3. Missing addresses (global + site)
        # ----------------------------------
        if "ipv6-site" not in kinds:
            data["warnings"].append(
                f"{net['name']}: prefijo site faltante (existentes: {', '.join(prefixes)})"
            )

        if "admin" not in net["name"].lower():  # you may refine later
            if "ipv6-global" not in kinds:
                data["warnings"].append(
                    f"{net['name']}: prefijo global faltante (existentes: {', '.join(prefixes)})"
                )

        # ----------------------------------
        # 4. Admin network should NOT have global
        # (basic heuristic: name contains 'Admin')
        # ----------------------------------
        if "admin" in net["name"].lower():
            if "global" in kinds:
                data["warnings"].append(
                    f"{net['name']}: red admin no debería usar direcciones globales"
                )

        # ----------------------------------
        # 5. P2P consistency
        # ----------------------------------
        if net["kind"] == "point-to-point":
            check_p2p_consistency(net, data)

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

        addrs = get_staticroute_interface_addresses(node_id, iface, data)
        #data["warnings"].append(f"node {node_id} for {iface}: found {addrs} IP addresses")

        global_ip = None
        site_ip = None

        for ip in addrs:
            if ip.version != 6:
                continue
            
            if classify_ipv6(ip) == "site":  # fd00::/8
                site_ip = ip
            elif classify_ipv6(ip) == "global":  # 2001::/16
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
            data["warnings"].append(
                f"{net['name']}: direcciones globales de distintos bloques ({a['global']} - {b['global']})"
            )

    # --- SITE CHECK ---
    if a["site"] and b["site"]:
        if not same_block(str(a["site"].network), str(b["site"].network)):
            data["warnings"].append(
                f"{net['name']}: direcciones site de distintos bloques ({a['site']} - {b['site']})"
            )

    # --- MISSING ADDRESS CHECK ---
    for ep in endpoints:
        if not ep["global"]:
            data["warnings"].append(
                f"{net['name']}: {data['devices'][ep['node']]['name']} ({ep['iface']}) sin dirección global"
            )
        if not ep["site"]:
            data["warnings"].append(
                f"{net['name']}: {data['devices'][ep['node']]['name']} ({ep['iface']}) sin dirección site"
            )

def same_block(p1, p2):
    n1 = ipaddress.ip_network(p1, strict=False)
    n2 = ipaddress.ip_network(p2, strict=False)

    return n1.network_address == n2.network_address and n1.prefixlen == n2.prefixlen

def get_staticroute_interface_addresses(node_id, iface_name, data):
    services = data["services"].get(node_id, {})
    text = services.get("StaticRoute", "")

    matches = re.findall(
        r'ip\s+-6\s+addr\s+add\s+([0-9a-fA-F:]+)\s*/\s*(\d+)\s+dev\s+([a-zA-Z0-9_.-]+)',
        text
    )

    #data["warnings"].append(f"node {node_id} for {iface_name}: found {matches} IP addresses")
    result = []

    for addr, mask, dev in matches:
        if dev == iface_name:
            try:
                ip = ipaddress.ip_interface(f"{addr}/{mask}")
                result.append(ip)
            except:
                pass

    return result

# --------------------------------------------------
# PREFIX EXTRACTION
# --------------------------------------------------

def get_prefixes_from_staticroute(node_id, iface_name, data):
    prefixes = set()
    services = data["services"].get(node_id, {})
    text = services.get("StaticRoute", "")

    matches = re.findall(
        r'ip\s+-6\s+addr\s+add\s+([0-9a-fA-F:]+)/(\d+)\s+dev\s+(\S+)',
        text
    )

    for addr, mask, dev in matches:
        if dev != iface_name:
            continue

        try:
            net = ipaddress.ip_network(f"{addr}/{mask}", strict=False)
            prefixes.add(str(net))
        except:
            pass

    return prefixes

def get_prefixes_from_radvd(node_id, iface_name, data):
    prefixes = set()
    services = data["services"].get(node_id, {})
    text = services.get("radvd", "")

    # Match full interface blocks (including inner braces)
    
    iface_blocks = re.findall(
        r'interface\s+(\S+)\s*\{((?:[^{}]|\{[^{}]*\})*)\}',
        text,
        re.DOTALL
    )

    for iface, body in iface_blocks:
        if iface != iface_name:
            continue

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

    return prefixes

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

def get_prefixes_for_interface(node_id, iface, data):
    if not iface:
        return set()

    iface_name = iface.get("name")
    prefixes = set()

    # 1. StaticRoute
    prefixes.update(get_prefixes_from_staticroute(node_id, iface_name, data))

    # 2. RADVD
    prefixes.update(get_prefixes_from_radvd(node_id, iface_name, data))

    # 3. Fallback (only if nothing found)
    if not prefixes:
        prefixes.update(get_prefixes_from_link_iface(iface))

    return prefixes

def classify_prefix(prefix):
    net = ipaddress.ip_network(prefix, strict=False)

    if net.version == 6:
        if net.network_address.exploded.startswith("fd"):
            return "ipv6-site"
        
        if net.network_address.exploded.startswith("2001"):
            return "ipv6-global"
    if net.version == 4:
        return "ipv4"
    
    return "unknown"

def classify_ipv6(ip):
    addr = ip.ip.exploded.lower()

    if addr.startswith("fd"):
        return "site"
    if addr.startswith("20") or addr.startswith("30"):
        return "global"
    return "other"
# --------------------------------------------------
# RADVD ALIGNMENT CHECK
# --------------------------------------------------
def get_radvd_interfaces(node_id, data):
    result = {}

    services = data["services"].get(node_id, {})
    text = services.get("radvd", "")

    iface_blocks = re.findall(
        r'interface\s+(\S+)\s*\{((?:[^{}]|\{[^{}]*\})*)\}',
        text,
        re.DOTALL
    )

    for iface, body in iface_blocks:
        prefixes = []

        matches = re.findall(
            r'prefix\s+([0-9a-fA-F:]+)/(\d+)',
            body
        )

        for addr, mask in matches:
            try:
                net = ipaddress.ip_network(f"{addr}/{mask}", strict=False)
                prefixes.append(net)
            except:
                pass

        if prefixes:
            result[iface] = prefixes

    return result

def get_staticroute_addresses(node_id, data):
    result = {}

    services = data["services"].get(node_id, {})
    text = services.get("StaticRoute", "")

    matches = re.findall(
        r'ip\s+-6\s+addr\s+add\s+([0-9a-fA-F:]+)/(\d+)\s+dev\s+(\S+)',
        text
    )

    for addr, mask, iface in matches:
        try:
            ip = ipaddress.ip_interface(f"{addr}/{mask}")
        except:
            continue

        if iface not in result:
            result[iface] = []

        result[iface].append(ip)

    return result

def validate_radvd_interfaces(data):
    for node_id, services in data["services"].items():
        if "radvd" not in services:
            continue

        node = data["devices"].get(node_id, {"name": f"node{node_id}"})
        node_name = node["name"]

        radvd_map = get_radvd_interfaces(node_id, data)
        addr_map = get_staticroute_addresses(node_id, data)
       
        for iface, prefixes in radvd_map.items():
            assigned_ips = addr_map.get(iface, [])

            if not assigned_ips:
                data["warnings"].append(
                    f"{node_name}: La interfaz {iface} tiene configurado radvd pero no se encontraron direcciones asignadas correspondientes al bloque anunciado ({', '.join(str(p) for p in prefixes)})"
                )
                continue

            for ip in assigned_ips:
                if not any(ip.ip in prefix for prefix in prefixes):
                    data["warnings"].append(
                        f"{node_name}: La dirección {ip} en la interfaz {iface} no pertenece a los bloques anunciados ({', '.join(str(p) for p in prefixes)})"
                    )

# --------------------------------------------------
# REPORT HELPERS
# --------------------------------------------------
def parse_l2_networks(root, data):
    nets = root.find("networks")
    if nets is None:
        return

    data["l2nodes"] = {}

    for net in nets.findall("network"):
        nid = net.get("id")
        name = net.get("name")
        ntype = net.get("type")

        data["l2nodes"][nid] = {
            "id": nid,
            "name": name,
            "type": ntype
        }


def get_node(data, node_id):
    if node_id in data["devices"]:
        return data["devices"][node_id]

    if node_id in data.get("l2nodes", {}):
        return data["l2nodes"][node_id]

    return {"id": node_id, "name": f"node{node_id}", "type": "unknown"}

def summarize(data):
    return {
        "devices_total": len(data["devices"]),
        "routers": len(data["routers"]),
        "links": len(data["links"]),
        "networks": len(data["networks"]),
        "warnings": data["warnings"]
    }


def pretty_networks(data):
    rows = []

    for _, net in data["networks"].items():
        rows.append({
            "name": net["name"],
            "kind": net["kind"],
            "members": net["members"],
            "prefixes": net["prefixes"]
        })

    return rows
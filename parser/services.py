import re
import ipaddress
from analyzer.prefixes import get_staticroute_interface_addresses, resolve_ip_owner, resolve_route_dev
from report.formatters import strip_comments
from utils.ip import NETWORK_GROUPS, PREFIX_TYPE, classify_prefix_type

# ---------------------------------------------------------------------
# Extracts service data into a structured format for later validation.
# ---------------------------------------------------------------------
def parse_services(root, data):
    section = root.find("service_configurations")
    if section is None:
        return

    for router in data["routers"].values():
        if router["id"] not in data["services"]:
            data["services"][router["id"]] = {}

    for svc in section.findall("service"):
        node = svc.get("node")
        name = svc.get("name")

        template = svc.find(".//template")
        text = template.text if template is not None and template.text else ""

        # 👇 limpiar comentarios acá
        text = strip_comments(text)

        if node not in data["services"]:
            data["services"][node] = {}

        data["services"][node][name] = text

# --------------------------------------------------------
# Parse all routing information from StaticRoute commands
# --------------------------------------------------------
def parse_routing(data):
    data["routing"] = {}
    for node_id, services in data["services"].items():
        if "StaticRoute" not in services:
            if node_id in data["routers"]:
                data["routing"][node_id] = {
                    "routes": [],
                    "rules": [],
                    "iptables": [],
                    "tunnels": [],
                    "warnings": {
                        "isp": [],
                        "tunnels": [],
                        "routing": []
                    }
                }
            continue

        text = services["StaticRoute"]

        data["routing"][node_id] = {
            "routes": parse_routes(text, data, node_id),
            "rules": parse_rules(text),
            "iptables": parse_ip6tables(text),
            "tunnels": parse_tunnels(text),
            "warnings": {
                "isp": [],
                "tunnels": [],
                "routing": []
            }
        }

# --------------
# Route parser
# --------------
def parse_routes(text, data, node_id):
    routes = []

    matches = re.findall(
        r'ip\s+(-6)?\s*route\s+add\s+(.*)',
        text
    )

    for route_index, (is_v6, line) in enumerate(matches, start=1):
        route = {
            "id": f"route-{node_id}-{route_index}",
            "family": PREFIX_TYPE["ipv6"] if is_v6 else PREFIX_TYPE["ipv4"],
            "type": "unicast",   # default
            "dst": None,
            "via": None,
            "dev": None,
            "table": "main"
        }

        # ----------------------------------
        # TYPE (blackhole / prohibit / unreachable / unicast)
        # ----------------------------------
        if re.search(r'\bblackhole\b', line):
            route["type"] = "blackhole"
        elif re.search(r'\bprohibit\b', line):
            route["type"] = "prohibit"
        elif re.search(r'\bunreachable\b', line):
            route["type"] = "unreachable"
        elif re.search(r'\bunicast\b', line):
            route["type"] = "unicast"

        # ----------------------------------
        # DESTINATION
        # (puede venir después del tipo o directo)
        # ----------------------------------
        dst = re.search(r'(?:blackhole|prohibit|unreachable|unicast)?\s*(default|[0-9a-fA-F\.:/]+)', line)
        
        if dst:
            route["dst"] = dst.group(1)

        route["networks"] = resolve_route_networks(route["dst"], data)
        # ----------------------------------
        # VIA (next-hop)
        # ----------------------------------
        via = re.search(r'via\s+(\S+)', line)
        if via:
            route["via"] = via.group(1)

         # ----------------------------------
        # DEV (interface)
        # ----------------------------------

        dev = re.search(r'dev\s+(\S+)', line)

        if dev:
            route["dev"] = dev.group(1)
        elif route["via"]:
            route["dev"] = resolve_route_dev(node_id, route["via"], data)
            #print(f"Resolving route dev for {route['dst']} via {route['via']} with dev {route['dev']}")

        if not route["via"] and route["dev"]:
            via_ip = resolve_p2p_route_via(node_id, route["dev"], route["family"], data)
            print(f"Debug {node_id} | {route["dev"]} | {route["type"]} | {via_ip}")
            if via_ip:
                route["via"] = via_ip
        # ----------------------------------
        # TABLE
        # ----------------------------------
        table = re.search(r'table\s+(\S+)', line)
        if table:
            route["table"] = table.group(1)

        routes.append(route)

    return routes


def resolve_p2p_route_via(node_id, dev, family, data):
    if not dev:
        return None

    for net in data.get("networks", {}).values():
        if net.get("kind") != "point-to-point":
            continue

        members = net.get("member_interfaces", [])
        local_member = next(
            (member for member in members if member["node"] == node_id and member["iface"] == dev),
            None
        )

        if not local_member:
            continue

        other_member = next(
            (member for member in members if member != local_member),
            None
        )

        if not other_member:
            continue

        print(other_member)

        peer_ip = get_staticroute_interface_addresses(data, other_member["node"], other_member["iface"])[0]
        #peer_ip = get_peer_interface_ip(other_member["node"], other_member["iface"], family, data)
        print(peer_ip)
        if peer_ip:
            return peer_ip.ip

    return None

# --------------
# Rule parser
# --------------
def parse_rules(text):
    rules = []

    matches = re.findall(
        r'ip\s+-6\s+rule\s+add\s+(.*)',
        text
    )

    for line in matches:
        rule = {
            "action": "unicast",
            "table": "main",
            "priority": None,
            "iif": None,
            "oif": None,
            "src": None,
            "dst": None,
            "fwmark": None,
            "ipproto": None
        }

        # ----------------------------------
        # PRIORITY (priority / pref / pri)
        # ----------------------------------
        prio = re.search(r'(?:priority|pref|pri)\s+(\d+)', line)
        if prio:
            rule["priority"] = int(prio.group(1))

        # ----------------------------------
        # SOURCE / DEST / IN/OUT INTERFACES
        # ----------------------------------
        src = re.search(r'from\s+(\S+)', line)
        dst = re.search(r'to\s+(\S+)', line)


        if src:
            rule["src"] = src.group(1)

        if dst:
            rule["dst"] = dst.group(1)
            
        iif = re.search(r'iif\s+(\S+)', line)
        oif = re.search(r'oif\s+(\S+)', line)
        
        if iif:
            rule["iif"] = iif.group(1)

        if oif:
            rule["oif"] = oif.group(1)

        # ----------------------------------
        # TABLE
        # ----------------------------------
        table = re.search(r'table\s+(\S+)', line)
        if table:
            rule["table"] = table.group(1)

        # ----------------------------------
        # FWMARK
        # ----------------------------------
        fwmark = re.search(r'fwmark\s+(\S+)', line)
        if fwmark:
            rule["fwmark"] = fwmark.group(1)

        # ----------------------------------
        # PROTOCOL (ipproto)
        # ----------------------------------
        proto = re.search(r'ipproto\s+(\S+)', line)
        if proto:
            rule["ipproto"] = proto.group(1)

        # ----------------------------------
        # ACTION
        # ----------------------------------

        if re.search(r'\bblackhole\b', line):
            rule["action"] = "blackhole"

        elif re.search(r'\bunreachable\b', line):
            rule["action"] = "unreachable"

        elif re.search(r'\bprohibit\b', line):
            rule["action"] = "prohibit"

        rules.append(rule)

    return rules

# --------------
# Firewall parser
# --------------
def parse_ip6tables(text):
    rules = []

    matches = re.findall(
        r'ip6tables\s+(.*)',
        text
    )

    for line in matches:
        rule = {
            "chain": None,
            "protocol": None,
            "mark": None,
            "target": None,
            "action": None,
            "src": None,
            "dst": None,
            "iif": None,
            "oif": None
        }

        chain = re.search(r'(!)?\s*-A\s+(\S+)', line)
        proto = re.search(r'(!)?\s*-p\s+(\S+)', line)
        mark = re.search(r'(!)?\s*--set-mark\s+(\S+)', line)
        target = re.search(r'(!)?\s*-j\s+(\S+)', line)
        src = re.search(r'(!)?\s*-s\s+(\S+)', line)
        dst = re.search(r'(!)?\s*-d\s+(\S+)', line)      
        iif = re.search(r'(!)?\s*-i\s+(\S+)', line)
        oif = re.search(r'(!)?\s*-o\s+(\S+)', line)

        if src:
            src_value = src.group(2)
            rule["src"] = f"not {src_value}" if src.group(1) else src_value

        if dst:
            dst_value = dst.group(2)
            rule["dst"] = f"not {dst_value}" if dst.group(1) else dst_value

        if iif:
            iif_value = iif.group(2)
            rule["iif"] = f"not {iif_value}" if iif.group(1) else iif_value

        if oif:
            oif_value = oif.group(2)
            rule["oif"] = f"not {oif_value}" if oif.group(1) else oif_value

        if chain:
            rule["chain"] = chain.group(2)

        if proto:
            proto_value = proto.group(2)
            rule["protocol"] = f"not {proto_value}" if proto.group(1) else proto_value

        if mark:
            mark_value = mark.group(2)
            rule["mark"] = f"not {mark_value}" if mark.group(1) else mark_value

        if target:
            target_value = target.group(2)
            rule["target"] = target_value

            tgt = target_value.upper()

            if tgt in ["DROP", "REJECT", "ACCEPT", "MARK", "LOG"]:
                rule["action"] = tgt
            else:
                rule["action"] = "OTHER"

        rules.append(rule)

    return rules

def parse_tunnels(text):

    tunnels = []

    matches = re.findall(
        r'ip\s+tunnel\s+add\s+(.+)',
        text
    )

    for line in matches:

        tunnel = {
            "name": None,
            "mode": None,
            "local": None,
            "remote": None,
            "dev": None
        }

        # ------------------------------
        # tunnel name
        # ------------------------------

        name = re.match(r'(\S+)', line)

        if name:
            tunnel["name"] = name.group(1)

        # ------------------------------
        # mode
        # ------------------------------

        mode = re.search(r'\bmode\s+(\S+)', line)

        if mode:
            tunnel["mode"] = mode.group(1)

        # ------------------------------
        # local
        # ------------------------------

        local = re.search(r'\blocal\s+(\S+)', line)

        if local:
            tunnel["local"] = local.group(1)

        # ------------------------------
        # remote
        # ------------------------------

        remote = re.search(r'\bremote\s+(\S+)', line)

        if remote:
            tunnel["remote"] = remote.group(1)

        # ------------------------------
        # dev
        # ------------------------------

        dev = re.search(r'\bdev\s+(\S+)', line)

        if dev:
            tunnel["dev"] = dev.group(1)

        tunnels.append(tunnel)

    return tunnels

def resolve_route_networks(route_dst, data):

    if not route_dst:
        return [NETWORK_GROUPS["unknown"]]

    if route_dst == PREFIX_TYPE["default"]:
        return [NETWORK_GROUPS["all"]]

    try:
        route_network = ipaddress.ip_network(route_dst, strict=False)
    except Exception:
        return [NETWORK_GROUPS["unknown"]]
    
    matched_networks = []

    for net in data["networks"].values():
        prefixes = [p for p in net["prefixes"] if p != "-"]
        network_name = net["name"]
        if not isinstance(prefixes, list):
            prefixes = [prefixes]

        for prefix in prefixes:

            try:
                candidate_network = ipaddress.ip_network(prefix, strict=False)

            except Exception:
                continue

            # different IP family
            if route_network.version != candidate_network.version:
                continue

            # exact
            if route_network == candidate_network:
                matched_networks.append(network_name)
                break

            # route contains candidate
            elif candidate_network.subnet_of(route_network):
                matched_networks.append(network_name)
                break

            # route more specific than candidate
            elif route_network.subnet_of(candidate_network):
                matched_networks.append(network_name)
                break

    if matched_networks:
        if(classify_prefix_type(route_dst) == PREFIX_TYPE["site"] and len(matched_networks) == 13):
            return [NETWORK_GROUPS["all"]]
        if(classify_prefix_type(route_dst) == PREFIX_TYPE["global"] and len(matched_networks) == 11):
            return [NETWORK_GROUPS["all"]]
        return matched_networks

    return [NETWORK_GROUPS["unknown"]]
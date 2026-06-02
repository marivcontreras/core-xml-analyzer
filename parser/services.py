import re
import ipaddress
from analyzer.prefixes import resolve_route_dev
from report.formatters import strip_comments
from utils.ip import PREFIX_TYPE, classify_prefix_type

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

    for is_v6, line in matches:
        route = {
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
            print(f"Route dev for {route['dst']} via {route['via']} with dev {dev.group(1)}")
            route["dev"] = dev.group(1)

        elif route["via"]:
            route["dev"] = resolve_route_dev(node_id, route["via"], data)
            print(f"Resolving route dev for {route['dst']} via {route['via']} with dev {route['dev']}")
        # ----------------------------------
        # TABLE
        # ----------------------------------
        table = re.search(r'table\s+(\S+)', line)
        if table:
            route["table"] = table.group(1)

        routes.append(route)

    return routes

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
        # SOURCE / DEST
        # ----------------------------------
        src = re.search(r'from\s+(\S+)', line)
        dst = re.search(r'to\s+(\S+)', line)

        if src:
            rule["src"] = src.group(1)

        if dst:
            rule["dst"] = dst.group(1)

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
            "src": None,
            "dst": None
        }

        chain = re.search(r'-A\s+(\S+)', line)
        proto = re.search(r'-p\s+(\S+)', line)
        mark = re.search(r'--set-mark\s+(\S+)', line)
        target = re.search(r'-j\s+(\S+)', line)
        src = re.search(r'-s\s+(\S+)', line)
        dst = re.search(r'-d\s+(\S+)', line)      

        if src:
            rule["src"] = src.group(1)

        if dst:
            rule["dst"] = dst.group(1)

        if chain:
            rule["chain"] = chain.group(1)

        if proto:
            rule["protocol"] = proto.group(1)

        if mark:
            rule["mark"] = mark.group(1)

        if target:
            rule["target"] = target.group(1)

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
        return ["unknown"]

    if route_dst == PREFIX_TYPE["default"]:
        return ["all"]

    try:
        route_network = ipaddress.ip_network(route_dst, strict=False)
    except Exception:
        return ["unknown"]
    
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
            return ["all"]
        if(classify_prefix_type(route_dst) == PREFIX_TYPE["global"] and len(matched_networks) == 11):
            return ["all"]
        return matched_networks

    return ["unknown"]
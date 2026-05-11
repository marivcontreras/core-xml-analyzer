import re


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

def parse_routes(text):
    routes = []

    matches = re.findall(
        r'ip\s+(-6)?\s*route\s+add\s+(.*)',
        text
    )

    for is_v6, line in matches:
        route = {
            "family": "ipv6" if is_v6 else "ipv4",
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

        # ----------------------------------
        # TABLE
        # ----------------------------------
        table = re.search(r'table\s+(\S+)', line)
        if table:
            route["table"] = table.group(1)

        routes.append(route)

    return routes

def parse_rules(text):
    rules = []

    matches = re.findall(
        r'ip\s+-6\s+rule\s+add\s+(.*)',
        text
    )

    for line in matches:
        rule = {
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

        rules.append(rule)

    return rules

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
import ipaddress

from utils import config_helper
from utils.firewall_config import get_expected_filters, get_expected_masquerade_routers
from utils.warning import add_routing_warning
from validation.configs.ip_commands_config import IPV4_CMD_EXTRACT_REGEX, IPV6_CMD_EXTRACT_REGEX


def is_masquerade(rule):
    return (rule.get("target") or "").upper() == "MASQUERADE"


def isp_interfaces(data, node_id):
    """Interface names of the router that face an internet (ISP) router."""
    internet_routers = set(
        config_helper.get_config().get("devices", {}).get("internet_routers", [])
    )
    interfaces = []

    for net in data["networks"].values():
        if net.get("kind") != "point-to-point":
            continue
        if not internet_routers.intersection(net["members"]):
            continue
        for member in net["member_interfaces"]:
            if member["node"] == node_id:
                interfaces.append(member["iface"]["name"])

    return interfaces


# Options of the expected command:
#   iptables -t nat -A POSTROUTING -o <iface> -j MASQUERADE
EXPECTED_OPTIONS = {
    "-4", "-6",
    "-t", "--table",
    "-A", "--append",
    "-o", "--out-interface",
    "-j", "--jump",
}
IN_INTERFACE_OPTIONS = {"-i", "--in-interface"}
SOURCE_OPTIONS = {"-s", "--source", "--src"}


def extra_options(command):
    """Return {option: value} for every option that is not part of the
    expected command, keeping the value (if any) that follows it."""
    tokens = command.split()[1:]
    found = {}

    for index, token in enumerate(tokens):
        if not token.startswith("-") or token in EXPECTED_OPTIONS:
            continue
        value = tokens[index + 1] if index + 1 < len(tokens) else ""
        found[token] = "" if value.startswith("-") else value

    return found


def validate_rule(rule, expected_oifs, warn):
    """Annotate a MASQUERADE rule with its problems (and emit warnings)."""
    problems = []
    command = rule["command"]

    table = rule.get("table") or "filter"
    if table != "nat":
        problems.append(warn("masquerade_wrong_table", ipt_table=table, command=command))

    if rule.get("chain") != "POSTROUTING":
        problems.append(warn("masquerade_wrong_chain", chain=rule.get("chain") or "-", command=command))

    oif = rule.get("oif")
    if not oif:
        problems.append(warn(
            "masquerade_no_oif",
            expected=", ".join(expected_oifs) or "la interfaz hacia el ISP",
            command=command,
        ))
    elif expected_oifs and oif not in expected_oifs:
        problems.append(warn(
            "masquerade_wrong_oif",
            expected=", ".join(expected_oifs),
            actual=oif,
            command=command,
        ))

    for option, value in extra_options(command).items():
        if option in IN_INTERFACE_OPTIONS:
            problems.append(warn("masquerade_in_interface", option_value=value, command=command))
        elif option in SOURCE_OPTIONS:
            problems.append(warn("masquerade_src", option_value=value, command=command))

    other = [f"{o} {v}".strip() for o, v in extra_options(command).items()
             if o not in IN_INTERFACE_OPTIONS and o not in SOURCE_OPTIONS]
    if other:
        problems.append(warn("masquerade_extra_option", options=", ".join(other), command=command))

    rule["problems"] = problems
    return rule


def validate_nat(data):
    """Evaluate MASQUERADE commands on routers.

    Stores the result in data["firewall"]["nat"]: one entry per router that is
    expected to NAT (see resources/<class>/firewall.yaml) or that applies
    MASQUERADE without being expected to.
    """
    expected_routers = get_expected_masquerade_routers()
    intranet_routers = config_helper.get_config().get("devices", {}).get("intranet_routers", [])
    entries = []

    for node_id, device in data["routers"].items():
        name = device["name"]
        expected = name in expected_routers
        if not expected and name not in intranet_routers:
            continue

        iptables = data["routing"].get(node_id, {}).get("iptables", [])
        masquerade_rules = [r for r in iptables if is_masquerade(r)]

        if not expected and not masquerade_rules:
            continue

        warnings = []

        def warn(code, **kwargs):
            before = len(warnings)
            add_routing_warning(None, "nat", code, warnings_list=warnings,
                                router=name, router_name=name, **kwargs)
            return warnings[-1]["message"] if len(warnings) > before else None

        expected_oifs = isp_interfaces(data, node_id) if expected else []

        if expected and not masquerade_rules:
            warn("missing_masquerade", expected=", ".join(expected_oifs) or "<interfaz hacia el ISP>")

        rules = []
        for rule in masquerade_rules:
            rule = dict(rule)
            if expected:
                validate_rule(rule, expected_oifs, warn)
            else:
                rule["problems"] = [warn("unexpected_masquerade", command=rule["command"])]
            rules.append(rule)

        entries.append({
            "router": name,
            "expected": expected,
            "expected_oifs": expected_oifs,
            "rules": rules,
            "warnings": warnings,
        })

    data["firewall"]["nat"] = sorted(entries, key=lambda e: e["router"])


# ---------------------------------------------------------------------------
# Expected filter commands (resources/<class>/firewall.yaml -> filters)
# ---------------------------------------------------------------------------

OPTION_KEYS = ("src", "dst", "iif", "oif", "protocol")
OPTION_FLAGS = {"iif": "-i", "protocol": "-p", "src": "-s", "dst": "-d", "oif": "-o"}
FIELD_LABELS = {
    "action": "acción (-j)",
    "src": "origen (-s)",
    "dst": "destino (-d)",
    "iif": "interfaz de entrada (-i)",
    "oif": "interfaz de salida (-o)",
    "protocol": "protocolo (-p)",
}
# Minimum share of matching fields for a found command to be reported as
# "the expected command, with differences" instead of as missing.
MIN_SIMILARITY = 0.5


def norm(value):
    """Normalize a field so equivalent values compare equal (10.0.0.1 == 10.0.0.1/32)."""
    if value is None:
        return None
    text = str(value)
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        return text


def network_key(name):
    """Case-insensitive, order-insensitive key for a network name (A<>B == b<>a)."""
    return frozenset(part.strip().lower() for part in str(name).split("<>"))


def member_interface(data, node_id, network_name):
    """Interface (dict) of the node that belongs to the given network."""
    wanted = network_key(network_name)
    for net in data["networks"].values():
        if network_key(net["name"]) != wanted:
            continue
        for member in net["member_interfaces"]:
            if member["node"] == node_id:
                return member["iface"]
    return None


def network_prefix(data, network_name):
    """First prefix assigned to the given network (None if unknown)."""
    wanted = network_key(network_name)
    for net in data["networks"].values():
        if network_key(net["name"]) == wanted:
            return next((p for p in net["prefixes"] if p != "-"), None)
    return None


def interface_address(data, node_id, iface):
    """IP address of an interface: from its `ip addr` command, else from CORE."""
    text = data["services"].get(node_id, {}).get("StaticRoute", "")
    for addr, mask, dev in IPV4_CMD_EXTRACT_REGEX.findall(text) + IPV6_CMD_EXTRACT_REGEX.findall(text):
        if dev == iface["name"]:
            return addr
    return iface.get("ip4") or iface.get("ip6")


def common_supernet(prefixes):
    """Smallest network containing all the given prefixes."""
    networks = [ipaddress.ip_network(p, strict=False) for p in prefixes]
    supernet = networks[0]
    while not all(n.subnet_of(supernet) for n in networks):
        supernet = supernet.supernet()
    return str(supernet)


def resolve_value(key, spec, data, node_id):
    """Resolve a {network|networks|host} spec to (value, note)."""
    if key in ("iif", "oif"):
        network = spec.get("network")
        iface = member_interface(data, node_id, network)
        return (iface["name"] if iface else f"<interfaz en la red {network}>"), f"red {network}"

    if "networks" in spec:
        prefixes = [network_prefix(data, n) for n in spec["networks"]]
        label = f"redes {', '.join(spec['networks'])}"
        if None in prefixes:
            return f"<bloque de las redes {', '.join(spec['networks'])}>", label
        return common_supernet(prefixes), label

    network = spec.get("network")
    if "host" in spec:
        host_id = next((i for i, d in data["devices"].items() if d["name"].lower() == spec["host"].lower()), None)
        iface = member_interface(data, host_id, network) if host_id else None
        address = interface_address(data, host_id, iface) if iface else None
        return (address or f"<IP de {spec['host']} en la red {network}>"), f"{spec['host']} en red {network}"

    return (network_prefix(data, network) or f"<bloque de la red {network}>"), f"red {network}"


def resolve_conditions(conditions, data, node_id, notes):
    """Replace dict specs in a command's conditions by values from the topology.

    Interface names, blocks and addresses depend on how each topology was
    built, so the config states where they come from instead:
      iif/oif : {network: X}              interface of the device in network X
      src/dst : {network: X}              block of network X
                {networks: [X, Y]}        smallest block containing those networks
                {host: H, network: X}     address of device H in network X
    """
    resolved = {}
    for key, value in (conditions or {}).items():
        if key not in OPTION_KEYS:
            continue
        if isinstance(value, dict):
            value, notes[key] = resolve_value(key, value, data, node_id)
        resolved[key] = value
    return resolved


def expected_view(expected, data, node_id):
    notes = {}
    options = resolve_conditions(expected.get("options"), data, node_id, notes)
    optional = resolve_conditions(expected.get("optional"), data, node_id, notes)
    return {
        "table": expected.get("table") or "filter",
        "chain": expected["chain"],
        "action": str(expected["action"]).upper(),
        "options": {k: options.get(k) for k in OPTION_KEYS},
        "optional": optional,
        "notes": notes,
    }


def found_view(rule):
    return {
        "table": rule.get("table") or "filter",
        "chain": rule.get("chain"),
        "action": (rule.get("target") or "").upper(),
        "options": {k: rule.get(k) for k in OPTION_KEYS},
    }


def format_expected(view):
    parts = ["iptables", "-t", view["table"], "-A", view["chain"]]
    for key in ("iif", "protocol", "src", "dst", "oif"):
        if view["options"].get(key) is not None:
            parts += [OPTION_FLAGS[key], str(view["options"][key])]
    parts += ["-j", view["action"]]
    text = " ".join(parts)
    networks = [f"{OPTION_FLAGS[k]}: {v}" for k, v in view["notes"].items()]
    if networks:
        text += f"  ({'; '.join(networks)})"
    optional = [f"{OPTION_FLAGS[k]} {v}" for k, v in view["optional"].items()]
    return f"{text}  (opcional: {', '.join(optional)})" if optional else text


def compare_fields(expected, found):
    """List of (field, expected value, found value) that differ."""
    pairs = [("action", expected["action"], found["action"])]
    for key in OPTION_KEYS:
        required, optional, actual = expected["options"][key], expected["optional"].get(key), found["options"][key]
        if required is None and optional is not None:
            # Optional condition: it may be absent, but if present it must match.
            if actual is not None and norm(actual) != norm(optional):
                pairs.append((key, f"{optional} (opcional)", actual))
            else:
                pairs.append((key, actual, actual))
        elif required is not None or actual is not None:
            pairs.append((key, required, actual))
    return [(f, e, a) for f, e, a in pairs if norm(e) != norm(a)], len(pairs)


def describe_diffs(diffs):
    return "; ".join(
        f"{FIELD_LABELS[field]} esperado {expected if expected is not None else 'ninguno'}, "
        f"actual {actual if actual is not None else 'ninguno'}"
        for field, expected, actual in diffs
    )


def related(a, b):
    """True if both values are IP blocks/addresses that overlap (10.0.0.1 vs 10.0.0.0/24)."""
    try:
        return ipaddress.ip_network(str(a), strict=False).overlaps(ipaddress.ip_network(str(b), strict=False))
    except ValueError:
        return False


def similarity_score(expected, found):
    """How alike an expected and a found command are, from 0 to 1.

    Every compared field scores 1 if equal, 0.5 if both are overlapping IP
    values that differ only in the mask (201.0.2.2 vs 201.0.2.2/24) and 0
    otherwise. Absent optional conditions are not compared.
    """
    scores = [1.0 if expected["action"] == found["action"] else 0.0]

    for key in OPTION_KEYS:
        required, optional, actual = expected["options"][key], expected["optional"].get(key), found["options"][key]
        wanted = required if required is not None else optional

        if wanted is None and actual is None:
            continue
        if required is None and actual is None:
            continue  # optional condition left out
        if wanted is not None and actual is not None and norm(wanted) == norm(actual):
            scores.append(1.0)
        elif wanted is not None and actual is not None and related(wanted, actual):
            scores.append(0.5)
        else:
            scores.append(0.0)

    return sum(scores) / len(scores)


def match_expected(views, found_views):
    """Pair every expected command with a found one.

    Returns {expected index: (found index, diffs)}; expected commands without
    a match are left out. Candidates (same table and chain) are paired from
    the most to the least similar, so the result does not depend on the order
    of the config. Then each expected command still unpaired takes a remaining
    command with the same action, if any, so it is reported as "differs"
    instead of "missing".
    """
    pairs = {}
    used = set()

    candidates = []
    for i, expected in enumerate(views):
        for j, found in enumerate(found_views):
            if found["table"] == expected["table"] and found["chain"] == expected["chain"]:
                candidates.append((similarity_score(expected, found), i, j))

    def assign(similar_enough):
        for similarity, i, j in sorted(candidates, key=lambda c: (-c[0], c[1], c[2])):
            if i in pairs or j in used or not similar_enough(i, j, similarity):
                continue
            pairs[i] = (j, compare_fields(views[i], found_views[j])[0])
            used.add(j)

    assign(lambda i, j, similarity: similarity >= MIN_SIMILARITY)
    assign(lambda i, j, similarity: views[i]["action"] == found_views[j]["action"])

    return pairs


def validate_filters(data):
    """Compare the expected filter commands with the ones found on each device.

    Stores the result in data["firewall"]["filters"]: one entry per device
    with expected commands, each row holding the found command (if any), its
    problems, and the found commands that were not evaluated.
    """
    expected_filters = get_expected_filters()
    entries = []

    for name, expected_list in expected_filters.items():
        node_id = next((i for i, d in data["devices"].items() if d["name"] == name), None)
        if node_id is None:
            continue

        # Only the filter table is evaluated here (nat is handled by its own sections).
        found_rules = [r for r in data["routing"].get(node_id, {}).get("iptables", [])
                       if (r.get("table") or "filter") == "filter"]
        views = [expected_view(e, data, node_id) for e in expected_list]
        found_views = [found_view(r) for r in found_rules]
        pairs = match_expected(views, found_views)

        warnings = []

        def warn(code, **kwargs):
            before = len(warnings)
            add_routing_warning(None, "filters", code, warnings_list=warnings,
                                router=name, router_name=name, **kwargs)
            return warnings[-1]["message"] if len(warnings) > before else None

        rows = []
        for i, (expected, view) in enumerate(zip(expected_list, views)):
            command = format_expected(view)
            row = {
                "consigna": expected.get("consigna"),
                "expected": command,
                "found_n": None,
                "problems": [],
                "diffs": [],
                "mismatch": None,
            }
            if i not in pairs:
                row["problems"].append(warn("missing_filter_rule", consigna=expected.get("consigna") or "-",
                                            expected=command))
            else:
                found_index, diffs = pairs[i]
                row["found_n"] = found_index + 1
                if diffs:
                    row["diffs"] = [{"field": FIELD_LABELS[f], "expected": e, "actual": a} for f, e, a in diffs]
                    row["mismatch"] = warn("filter_rule_mismatch", consigna=expected.get("consigna") or "-",
                                           differences=describe_diffs(diffs))
                    row["problems"].append(row["mismatch"])
            rows.append(row)

        # Order: it only matters for the commands flagged `last: true` (e.g. a
        # catch-all REJECT), which must come after every other expected command
        # of their chain (first match wins). Everything else may go in any order.
        for i, view in enumerate(views):
            if i not in pairs or not expected_list[i].get("last"):
                continue
            found_index = pairs[i][0]
            later = [rows[k]["expected"] for k, other in enumerate(views)
                     if k != i and k in pairs and pairs[k][0] > found_index
                     and (other["table"], other["chain"]) == (view["table"], view["chain"])]
            if later:
                rows[i]["problems"].append(warn(
                    "filter_rule_order", consigna=expected_list[i].get("consigna") or "-",
                    expected=rows[i]["expected"], previous="; ".join(later)))

        # Preview of every iptables command found on the device, numbered in
        # the order they appear; the analysis rows point to these numbers.
        commands = []
        for j, rule in enumerate(found_rules):
            consigna, status = None, "unevaluated"
            for i, (found_index, _) in pairs.items():
                if found_index == j:
                    consigna = rows[i]["consigna"]
                    status = "error" if rows[i]["problems"] else "ok"
            commands.append({"n": j + 1, "command": rule["command"], "consigna": consigna, "status": status})

        entries.append({
            "router": name,
            "commands": commands,
            "rows": rows,
            "warnings": warnings,
        })

    data["firewall"]["filters"] = entries

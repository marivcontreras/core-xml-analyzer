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

OPTION_KEYS = ("src", "dst", "iif", "oif", "protocol", "dport", "to")
OPTION_FLAGS = {"iif": "-i", "protocol": "-p", "src": "-s", "dst": "-d", "oif": "-o",
                "dport": "--dport", "to": "--to-destination"}
FIELD_LABELS = {
    "action": "acción (-j)",
    "src": "origen (-s)",
    "dst": "destino (-d)",
    "iif": "interfaz de entrada (-i)",
    "oif": "interfaz de salida (-o)",
    "protocol": "protocolo (-p)",
    "dport": "puerto de destino (--dport)",
    "to": "destino de la traducción (--to-destination)",
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
        return (iface["name"] if iface else f"<interfaz en la red {network}>"), f"eth en red {network}"

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
        address = address or f"<IP de {spec['host']} en la red {network}>"
        if "port" in spec:  # translation target: address:port
            address = f"{address}:{spec['port']}"
        return address, f"{spec['host']} en red {network}"

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


def expected_actions(expected):
    """Accepted targets (-j) of an expected command, upper-cased (`action` is a list)."""
    actions = expected["action"]
    if isinstance(actions, str):
        actions = [actions]
    return [str(a).upper() for a in actions]


def action_text(view):
    """Accepted targets of an expected command, for display (REJECT o DROP)."""
    return " o ".join(view["action"])


def expected_view(expected, data, node_id):
    notes = {}
    options = resolve_conditions(expected.get("options"), data, node_id, notes)
    optional = resolve_conditions(expected.get("optional"), data, node_id, notes)
    return {
        "table": expected.get("table") or "filter",
        "chain": expected["chain"],
        "action": expected_actions(expected),
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
    for key in ("iif", "protocol", "src", "dst", "oif", "dport"):
        if view["options"].get(key) is not None:
            parts += [OPTION_FLAGS[key], str(view["options"][key])]
    parts += ["-j", action_text(view)]
    if view["options"].get("to") is not None:
        parts += [OPTION_FLAGS["to"], str(view["options"]["to"])]
    text = " ".join(parts)
    networks = [f"{OPTION_FLAGS[k]}: {v}" for k, v in view["notes"].items()]
    if networks:
        text += f"  ({'; '.join(networks)})"
    optional = [f"{OPTION_FLAGS[k]} {v}" for k, v in view["optional"].items()]
    return f"{text}  (opcional: {', '.join(optional)})" if optional else text


def expected_segments(view, error_keys):
    """The expected command split in pieces for display, flagging the ones
    whose field (action, src, iif...) differs from the found command.

    Returns {"parts": command pieces, "notes": where each value comes from,
    "optional": optional conditions}; each item is {"text", "error"}.
    """
    parts = [{"text": f"iptables -t {view['table']} -A {view['chain']}", "error": False}]
    for key in ("iif", "protocol", "src", "dst", "oif", "dport"):
        if view["options"].get(key) is not None:
            parts.append({"text": f"{OPTION_FLAGS[key]} {view['options'][key]}", "error": key in error_keys})
    parts.append({"text": f"-j {action_text(view)}", "error": "action" in error_keys})
    if view["options"].get("to") is not None:
        parts.append({"text": f"{OPTION_FLAGS['to']} {view['options']['to']}", "error": "to" in error_keys})

    return {
        "parts": parts,
        "notes": [{"text": f"{OPTION_FLAGS[k]}: {v}", "error": k in error_keys} for k, v in view["notes"].items()],
        "optional": [{"text": f"{OPTION_FLAGS[k]} {v}", "error": k in error_keys} for k, v in view["optional"].items()],
    }


def compare_fields(expected, found):
    """List of (field, expected value, found value) that differ."""
    accepted = found["action"] in expected["action"]
    pairs = [("action", found["action"] if accepted else action_text(expected), found["action"])]
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
    scores = [1.0 if found["action"] in expected["action"] else 0.0]

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
    assign(lambda i, j, similarity: found_views[j]["action"] in views[i]["action"])

    return pairs


def rules_in_tables(data, node_id, tables):
    """iptables commands of a device in the given tables, leaving out MASQUERADE
    (evaluated by validate_nat)."""
    return [r for r in data["routing"].get(node_id, {}).get("iptables", [])
            if (r.get("table") or "filter") in tables and not is_masquerade(r)]


def filter_rules(data, node_id):
    """iptables commands of the filter table found on a device."""
    return rules_in_tables(data, node_id, {"filter"})


def make_warn(name, warnings, category="filters"):
    """Function that records a `category` warning for device `name` in `warnings`
    and returns its message (None if the warning is disabled)."""
    def warn(code, **kwargs):
        before = len(warnings)
        add_routing_warning(None, category, code, warnings_list=warnings,
                            router=name, router_name=name, **kwargs)
        return warnings[-1]["message"] if len(warnings) > before else None
    return warn


def is_same_filter(expected, found):
    """True if a found command is the expected one wherever it is applied.

    Interfaces are not compared (they differ from device to device): the
    command must have the same table, chain, action and protocol/source/
    destination. Commands without a source or destination (e.g. a catch-all
    REJECT on an interface) are too generic to be recognized elsewhere.
    """
    options, actual = expected["options"], found["options"]
    if options["src"] is None and options["dst"] is None:
        return False
    if (expected["table"], expected["chain"]) != (found["table"], found["chain"]) \
            or found["action"] not in expected["action"]:
        return False
    return all(norm(options[key]) == norm(actual[key]) for key in ("src", "dst", "protocol"))


def find_misplaced(data, entries, owners):
    """Find expected commands applied on a device other than the one they belong to.

    owners: {device name: (node id, expected views, expected commands)}.
    A command should be applied on its own device (e.g. R6) so packets are
    filtered where they are meant to be, instead of travelling through other
    parts of the network (R3, R5) first. Each hit is stored in the `misplaced`
    list of the device where it was found (creating its entry if needed) and
    in the `found_elsewhere` list of the expected row of its owner.
    """
    by_router = {entry["router"]: entry for entry in entries}

    for node_id, device in data["devices"].items():
        name = device["name"]
        found_rules = filter_rules(data, node_id)
        hits = []

        for j, rule in enumerate(found_rules):
            found = found_view(rule)
            for owner, (owner_id, views, expected_list) in owners.items():
                if owner_id == node_id:
                    continue
                for i, view in enumerate(views):
                    if is_same_filter(view, found):
                        hits.append((j, owner, i, expected_list[i]))

        if not hits:
            continue

        entry = by_router.get(name)
        if entry is None:
            entry = {
                "router": name,
                "commands": [{"n": j + 1, "command": r["command"], "consigna": None, "status": "unevaluated"}
                             for j, r in enumerate(found_rules)],
                "rows": [],
                "misplaced": [],
                "warnings": [],
            }
            entries.append(entry)
            by_router[name] = entry
        warn = make_warn(name, entry["warnings"])

        for j, owner, i, expected in hits:
            consigna = expected.get("consigna") or "-"
            command = entry["commands"][j]
            command["consigna"] = f"{consigna} (corresponde a {owner})"
            command["status"] = "misplaced"
            entry["misplaced"].append({
                "n": j + 1,
                "command": command["command"],
                "owner": owner,
                "consigna": consigna,
                "message": warn("filter_rule_misplaced", consigna=consigna, owner=owner,
                                n=j + 1, command=command["command"]),
            })

            owner_entry = by_router.get(owner)
            if owner_entry:
                owner_entry["rows"][i]["found_elsewhere"].append(f"{name} (N° {j + 1})")


def validate_filters(data):
    """Compare the expected filter commands with the ones found on each device.

    Stores the result in data["firewall"]["filters"]: one entry per device
    with expected commands, each row holding the found command (if any), its
    problems, and the found commands that were not evaluated. Commands of
    one device found on another are listed in the latter's `misplaced`.
    """
    expected_filters = get_expected_filters()
    entries = []
    owners = {}

    for name, expected_list in expected_filters.items():
        node_id = next((i for i, d in data["devices"].items() if d["name"] == name), None)
        if node_id is None:
            continue

        tables = {e.get("table") or "filter" for e in expected_list}
        found_rules = rules_in_tables(data, node_id, tables)
        views = [expected_view(e, data, node_id) for e in expected_list]
        found_views = [found_view(r) for r in found_rules]
        pairs = match_expected(views, found_views)
        owners[name] = (node_id, views, expected_list)

        warnings = []
        warn = make_warn(name, warnings)

        rows = []
        for i, (expected, view) in enumerate(zip(expected_list, views)):
            command = format_expected(view)
            row = {
                "consigna": expected.get("consigna"),
                "expected": command,
                "found_n": None,
                "found_command": None,
                "problems": [],
                "diffs": [],
                "mismatch": None,
                "found_elsewhere": [],
            }
            diff_keys = set()
            if i not in pairs:
                row["problems"].append(warn("missing_filter_rule", consigna=expected.get("consigna") or "-",
                                            expected=command))
            else:
                found_index, diffs = pairs[i]
                row["found_n"] = found_index + 1
                row["found_command"] = found_rules[found_index]["command"]
                if diffs:
                    diff_keys = {f for f, _, _ in diffs}
                    row["diffs"] = [{"field": FIELD_LABELS[f], "expected": e, "actual": a} for f, e, a in diffs]
                    row["mismatch"] = warn("filter_rule_mismatch", consigna=expected.get("consigna") or "-",
                                           differences=describe_diffs(diffs))
                    row["problems"].append(row["mismatch"])
            row["expected_parts"] = expected_segments(view, diff_keys)
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
            "misplaced": [],
            "warnings": warnings,
        })

    find_misplaced(data, entries, owners)
    find_policies(data, entries)
    find_unmatched(data, entries)
    data["firewall"]["filters"] = entries


def find_policies(data, entries):
    """Error for filter chains whose default policy is set to DROP or REJECT.

    The default policy applies to all the traffic of the chain, while the
    consignas only block outgoing traffic (with explicit rules).
    """
    by_router = {entry["router"]: entry for entry in entries}

    for node_id, device in data["routers"].items():
        name = device["name"]
        bad = [r for r in data["routing"].get(node_id, {}).get("iptables", [])
               if r.get("policy") in ("DROP", "REJECT")
               and (r.get("table") or "filter") == "filter"]
        if not bad:
            continue

        entry = by_router.get(name)
        if entry is None:
            entry = {"router": name, "commands": [], "rows": [], "misplaced": [], "warnings": []}
            entries.append(entry)
        warn = make_warn(name, entry["warnings"])
        errors = entry.setdefault("policy_errors", {})
        for rule in bad:
            errors[rule["command"]] = warn("filter_default_policy", command=rule["command"],
                                           chain=rule["policy_chain"], policy=rule["policy"])


def describe_address(data, value):
    """Which network or device an address/block of a command refers to, in words."""
    try:
        block = ipaddress.ip_network(str(value), strict=False)
    except ValueError:
        return None

    nets = []
    for net in data["networks"].values():
        for prefix in net["prefixes"]:
            try:
                network = ipaddress.ip_network(prefix, strict=False)
            except ValueError:
                continue
            if network.version == block.version:
                nets.append((net, network))

    if block.num_addresses == 1:
        for net in data["networks"].values():
            for member in net["member_interfaces"]:
                address = interface_address(data, member["node"], member["iface"])
                try:
                    same = address and ipaddress.ip_address(address.split("/")[0]) == block.network_address
                except ValueError:
                    same = False
                if same:
                    return f"dirección de {data['devices'][member['node']]['name']} en la red {net['name']}"

    exact = [n["name"] for n, network in nets if network == block]
    if exact:
        return f"bloque de la red {exact[0]}"
    inside = [n["name"] for n, network in nets if block.subnet_of(network)]
    if inside:
        return f"dentro del bloque de la red {inside[0]}"
    contained = sorted({n["name"] for n, network in nets if network.subnet_of(block)})
    if contained:
        return f"bloque que agrupa las redes {', '.join(contained)}"
    return "no pertenece a ninguna red de la topología"


def interpret_command(data, node_id, rule):
    """Plain-language reading of the options of an iptables command, e.g.
    "-i eth1: interfaz hacia la red wlan-Inv", for commands no consigna claims."""
    lines = []

    for key in ("iif", "oif"):
        name = rule.get(key)
        if not name:
            continue
        network = next((net["name"] for net in data["networks"].values()
                        for m in net["member_interfaces"]
                        if m["node"] == node_id and m["iface"]["name"] == name), None)
        text = f"interfaz hacia la red {network}" if network else "interfaz sin red asignada en la topología"
        lines.append(f"{OPTION_FLAGS[key]} {name}: {text}")

    for key in ("src", "dst"):
        if rule.get(key):
            text = describe_address(data, rule[key])
            if text:
                lines.append(f"{OPTION_FLAGS[key]} {rule[key]}: {text}")

    to = rule.get("to")
    if to:
        text = describe_address(data, str(to).rsplit(":", 1)[0])
        if text:
            lines.append(f"{OPTION_FLAGS['to']} {to}: {text}")

    return lines


def find_unmatched(data, entries):
    """Warn about iptables commands that do not correspond to any consigna.

    MASQUERADE is left out (validate_nat evaluates it). A command is
    claimed if it was paired with an expected command or recognized as one
    applied on the wrong device. The warning goes in the device's entry
    (created if it has no expected commands).
    """
    by_router = {entry["router"]: entry for entry in entries}
    claimed = {(entry["router"], c["command"])
               for entry in entries for c in entry["commands"] if c["consigna"]}

    for node_id, device in data["routers"].items():
        name = device["name"]
        commands = [r["command"] for r in data["routing"].get(node_id, {}).get("iptables", [])
                    if not is_masquerade(r) and not r.get("policy")
                    and (name, r["command"]) not in claimed]
        if not commands:
            continue

        entry = by_router.get(name)
        if entry is None:
            entry = {"router": name, "commands": [], "rows": [], "misplaced": [], "warnings": []}
            entries.append(entry)
        warn = make_warn(name, entry["warnings"])
        for command in commands:
            warn("filter_rule_unmatched", command=command)

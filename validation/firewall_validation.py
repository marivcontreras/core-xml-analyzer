from utils import config_helper
from utils.firewall_config import get_expected_masquerade_routers
from utils.warning import add_routing_warning


def _is_masquerade(rule):
    return (rule.get("target") or "").upper() == "MASQUERADE"


def _isp_interfaces(data, node_id):
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
_EXPECTED_OPTIONS = {
    "-4", "-6",
    "-t", "--table",
    "-A", "--append",
    "-o", "--out-interface",
    "-j", "--jump",
}
_IN_INTERFACE_OPTIONS = {"-i", "--in-interface"}
_SOURCE_OPTIONS = {"-s", "--source", "--src"}


def _extra_options(command):
    """Return {option: value} for every option that is not part of the
    expected command, keeping the value (if any) that follows it."""
    tokens = command.split()[1:]
    found = {}

    for index, token in enumerate(tokens):
        if not token.startswith("-") or token in _EXPECTED_OPTIONS:
            continue
        value = tokens[index + 1] if index + 1 < len(tokens) else ""
        found[token] = "" if value.startswith("-") else value

    return found


def _validate_rule(rule, expected_oifs, warn):
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

    for option, value in _extra_options(command).items():
        if option in _IN_INTERFACE_OPTIONS:
            problems.append(warn("masquerade_in_interface", option_value=value, command=command))
        elif option in _SOURCE_OPTIONS:
            problems.append(warn("masquerade_src", option_value=value, command=command))

    other = [f"{o} {v}".strip() for o, v in _extra_options(command).items()
             if o not in _IN_INTERFACE_OPTIONS and o not in _SOURCE_OPTIONS]
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
        masquerade_rules = [r for r in iptables if _is_masquerade(r)]

        if not expected and not masquerade_rules:
            continue

        warnings = []

        def warn(code, **kwargs):
            before = len(warnings)
            add_routing_warning(None, "nat", code, warnings_list=warnings,
                                router=name, router_name=name, **kwargs)
            return warnings[-1]["message"] if len(warnings) > before else None

        expected_oifs = _isp_interfaces(data, node_id) if expected else []

        if expected and not masquerade_rules:
            warn("missing_masquerade", expected=", ".join(expected_oifs) or "<interfaz hacia el ISP>")

        rules = []
        for rule in masquerade_rules:
            rule = dict(rule)
            if expected:
                _validate_rule(rule, expected_oifs, warn)
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

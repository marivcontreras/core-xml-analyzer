from analyzer.prefixes import resolve_ip_owner
from parser.services import resolve_route_networks
from resources.warnings import get_warning
from validation.policy_validation import validate_policy


def build_behavior_and_tag(item, data, initial_tag=None, behavior_type="rule"):
    """
    Build behavior dict and tag based on item attributes.
    Checks src, dst, iif, oif, and fwmark attributes.
    
    Args:
        item: rule/iptables/route dict
        data: full data dict for resolving networks
        initial_tag: initial tag value (e.g., "tcp", "action_value")
        behavior_type: 'rule', 'iptables', or 'route'
    
    Returns:
        tuple of (tag, behavior)
    """
    tag = initial_tag
    behavior = {
        "type": behavior_type,
        "options": {},
        "table": None,
        "src_networks": {},
        "dst_networks": {},
        "via": {}
    }
    
    if item.get("ipproto"):
        behavior["options"]["ipproto"] = item['ipproto']
        tag = f"{tag}_ipproto" if tag else "ipproto"

    # Check src protocol
    if item.get("protocol"):
        behavior["options"]["protocol"] = item['protocol']
        tag = f"{tag}_protocol" if tag else "protocol"

    # Check src attribute
    if item.get("src"):
        behavior["options"]["src"] = item['src']
        tag = f"{tag}_src" if tag else "src"
        behavior["src_networks"] = resolve_route_networks(item["src"], data)
    
    # Check dst attribute
    if item.get("dst"):
        behavior["options"]["dst"] = item['dst']
        tag = f"{tag}_dst" if tag else "dst"
        behavior["dst_networks"] = resolve_route_networks(item["dst"], data)
    
    # Check iif attribute
    if item.get("iif"):
        behavior["options"]["iif"] = item['iif']
        tag = f"{tag}_iif" if tag else "iif"
    
    # Check oif attribute
    if item.get("oif"):
        behavior["options"]["oif"] = item['oif']
        tag = f"{tag}_oif" if tag else "oif"
    
    # Check fwmark attribute
    if item.get("fwmark"):
        behavior["options"]["fwmark"] = item['fwmark']
        tag = f"{tag}_fwmark" if tag else "fwmark"
    
    if item.get("mark"):
        behavior["options"]["mark"] = item['mark']
        tag = f"{tag}_fwmark" if tag else "fwmark"
    

    return tag, behavior


def add_default_route_via(behavior, table, routes, data):
    """Set behavior['via'] from the default route of a table if present."""
    if not table:
        return
    default_route = next(
        (
            r for r in routes
            if r.get("table") == table and r.get("dst") == "default"
        ),
        None,
    )

    if default_route and default_route.get("via"):
        behavior["via"] = resolve_ip_owner(default_route["via"], data)


def process_iptables(policy, iptables, data, extra_actions=None):
    """Normalize iptables list into policy['behavior']."""
    for r in iptables:
        initial_tag = None
        actions = ["DROP", "REJECT", "ACCEPT"]
        if extra_actions:
            actions = list(set(actions + list(extra_actions)))
        if r.get("action") in actions:
            initial_tag = r.get("action")

        tag, behavior = build_behavior_and_tag(r, data, initial_tag, "iptables")

        if tag:
            policy["behavior"][tag] = behavior


def process_rules(policy, rules, routes, data, mode="ipproto", add_priority=False):
    """Normalize ip rule list into policy['behavior'].

    mode: 'ipproto' to use rule['ipproto']=='tcp' as initial tag,
          'action' to use rule['action'] as initial tag.
    """
    for rule in rules:
        if mode == "ipproto":
            initial_tag = "tcp" if rule.get("ipproto") == "tcp" else None
        else:
            initial_tag = rule.get("action") if rule.get("action") else None

        tag, behavior = build_behavior_and_tag(rule, data, initial_tag, "rule")

        if not tag:
            tag = "other"

        if add_priority and rule.get("priority") is not None:
            tag = f"{tag}_pri_{rule['priority']}"

        if rule.get("table"):
            behavior["table"] = rule["table"]

        if tag:
            add_default_route_via(behavior, rule.get("table"), routes, data)
            policy["behavior"][tag] = behavior


def process_routes(policy, routes, data):
    """Normalize route entries into policy['behavior']."""
    for r in routes:
        tag = None
        behavior = {
            "type": "route",
            "table": None,
            "src_networks": {},
            "dst_networks": {},
            "via": {},
        }

        if (
            r.get("type") in ["prohibit", "blackhole", "unreachable"]
            or r.get("dst") == "default"
            or (r.get("type") == "unicast" and r.get("table") != "main")
        ):

            tag = f"{r.get('table')}_{r.get('type')}_{r.get('dst')}"
            behavior["table"] = r.get("table")
            behavior["dst_networks"] = resolve_route_networks(r.get("dst"), data)

            if r.get("via"):
                behavior["via"] = resolve_ip_owner(r.get("via"), data)
            policy["behavior"][tag] = behavior



def analyze_policies(data):
    for node_id, router in data["routers"].items():
        name = router["name"]

        if name == "R4":
            analyze_r4_policy(data, node_id)

        elif name == "R5":
            analyze_r5_policy(data, node_id)

def analyze_r4_policy(data, node_id):
    routing = data["routing"][node_id]

    routes = routing["routes"]
    rules = routing["rules"]
    iptables = routing["iptables"]

    policy = {
        "router": "R4",
        "approach": [],
        "behavior": {},
        "evidence": [],
        "warnings": []
    }

    # --------------------------------------------------
    # Detect fwmark approach
    # --------------------------------------------------

    mark_rules = [r for r in rules if r["fwmark"]]

    mark_iptables = [
        r for r in iptables
        if r["action"] == "MARK"
    ]

    if mark_rules and mark_iptables:
        policy["approach"] = ["fwmark"]
        
        policy["evidence"].append(get_warning("tcp_approach_iptables"))


    # --------------------------------------------------
    # Detect ipproto approach
    # --------------------------------------------------

    elif any(r["ipproto"] == "tcp" for r in rules):
        policy["approach"] = "ipproto"

        policy["evidence"].append(get_warning("tcp_approach_iprule"))

    else:
        policy["approach"] = "custom"

    # --------------------------------------------------
    # Infer behavior for each rule
    # --------------------------------------------------

    # --------------------------------------------------
    # Filtering con iptables
    # --------------------------------------------------

    process_iptables(policy, iptables, data, extra_actions=["MARK"])

    process_rules(policy, rules, routes, data, mode="ipproto", add_priority=False)

    process_routes(policy, routes, data)

    print(f"R4 policy: {policy}")
    policy["warnings"] = validate_policy(data, node_id, policy)
    routing["policy"] = policy


def analyze_r5_policy(data, node_id):
    routing = data["routing"][node_id]

    routes = routing["routes"]
    rules = routing["rules"]
    iptables = routing["iptables"]

    policy = {
        "router": "R5",
        "approach": [],
        "behavior": {},
        "evidence": [],
        "warnings": []
    }

    # --------------------------------------------------
    # Detect approach
    # --------------------------------------------------

    if any(r["action"] in ["prohibit", "blackhole", "unreachable"] for r in rules):
        policy["approach"].append("ip-rule-filtering")

    if any(r["type"] in ["prohibit", "blackhole", "unreachable"] for r in routes):
        policy["approach"].append("policy-table-filtering")

    if any(r["action"] in ["DROP", "REJECT"] for r in iptables ):
        policy["approach"].append("iptables-filtering")

    if policy["approach"] == []:
        policy["approach"].append("unknown")

    # --------------------------------------------------
    # Filtering con iptables
    # --------------------------------------------------

    process_iptables(policy, iptables, data)

    # --------------------------------------------------
    # Reglas de filtrado basadas en ip rule
    # --------------------------------------------------
    process_rules(policy, rules, routes, data, mode="action", add_priority=True)
    
    # --------------------------------------------------
    # Filtering con ip route
    # --------------------------------------------------

    process_routes(policy, routes, data)
    
   
    print(f"R5 policy: {policy}")
    routing["policy"] = policy
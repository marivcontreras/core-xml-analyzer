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

    for r in iptables:
        # Determine initial tag based on action
        initial_tag = None
        if r["action"] in ["DROP", "REJECT", "ACCEPT", "MARK"]:
            initial_tag = r["action"]
        
        tag, behavior = build_behavior_and_tag(r, data, initial_tag, "iptables")

        if tag:
            policy["behavior"][tag] = behavior

    for rule in rules:
        # Determine initial tag based on ipproto
        initial_tag = ""
        if rule["ipproto"] == "tcp":
            initial_tag = "tcp"
        
        tag, behavior = build_behavior_and_tag(rule, data, initial_tag if initial_tag else None, "rule")
        
        if not tag:
            tag = "other"

        if rule["table"]:
            behavior["table"] = rule["table"]
            
        if tag:
            # Find default route for this table
            default_route = next(
                (
                    r for r in routes
                    if r["table"] == rule["table"]
                    and r["dst"] == "default"
                ),
                None
            )

            if default_route and default_route["via"]:
                behavior["via"] = resolve_ip_owner(default_route["via"], data)

            policy["behavior"][tag] = behavior

    for r in routes:
        tag = None
        behavior = {
            "type" : "route",
            "table" : None,
            "src_networks" : {},
            "dst_networks" : {},
            "via": {}            
        }
        
        if (r["type"] in ["prohibit", "blackhole", "unreachable"] or
            r["dst"] == "default" or
            (r["type"] == "unicast" and r["table"] != "main")):

            tag = f"{r["table"]}_{r["type"]}_{r["dst"]}"
            behavior["table"] = r["table"]
            behavior["dst_networks"] = resolve_route_networks(r["dst"], data)

            if r["via"]:
                behavior["via"] = resolve_ip_owner(r["via"], data)
            policy["behavior"][tag] = behavior

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

    for r in iptables:
        # Determine initial tag based on action
        initial_tag = None
        if r["action"] in ["DROP", "REJECT", "ACCEPT"]:
            initial_tag = r["action"]
        
        tag, behavior = build_behavior_and_tag(r, data, initial_tag, "iptables")

        if tag:
            policy["behavior"][tag] = behavior

    # --------------------------------------------------
    # Reglas de filtrado basadas en ip rule
    # --------------------------------------------------
    for rule in rules:
        # Determine initial tag based on action
        initial_tag = None
        if rule["action"]:
            initial_tag = f"{rule['action']}"
        
        tag, behavior = build_behavior_and_tag(rule, data, initial_tag, "rule")
        
        if not tag:
            tag = "other"

        tag = f"{tag}_pri_{rule['priority']}"

        if rule["table"]:
            behavior["table"] = rule["table"]
        # Create behavior entry with table and via
        if tag:

            # Find default route for this table
            default_route = next(
                (
                    r for r in routes
                    if r["table"] == rule["table"]
                    and r["dst"] == "default"
                ),
                None
            )

            if default_route and default_route["via"]:
                behavior["via"] = resolve_ip_owner(default_route["via"], data)

            policy["behavior"][tag] = behavior
    
    # --------------------------------------------------
    # Filtering con ip route
    # --------------------------------------------------

    for r in routes:
        tag = None
        behavior = {
            "type" : "route",
            "table" : None,
            "src_networks" : {},
            "dst_networks" : {},
            "via": {}            
        }
        
        if (r["type"] in ["prohibit", "blackhole", "unreachable"] or
            r["dst"] == "default" or
            (r["type"] == "unicast" and r["table"] != "main")):

            tag = f"{r["table"]}_{r["type"]}_{r["dst"]}"
            behavior["table"] = r["table"]
            behavior["dst_networks"] = resolve_route_networks(r["dst"], data)

            if r["via"]:
                behavior["via"] = resolve_ip_owner(r["via"], data)
            policy["behavior"][tag] = behavior
    
   
    print(f"R5 policy: {policy}")
    routing["policy"] = policy
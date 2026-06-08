from webbrowser import get

from resources.warnings import get_warning


def validate_policy(data, node_id, policy):
    # Placeholder for policy validation logic
    # This function will analyze the policy behavior and generate warnings based on validation rules
    warnings = []

    # Example validation rule (to be expanded after audit):
    # If policy approach is "fwmark" but no tcp-specific rules are found, add a warning
    if policy["approach"] == "fwmark":
        tcp_rules = [r for r in data["routing"][node_id]["iptables"] if r.get("protocol") == "tcp"]
        if not tcp_rules:
            warnings.append(get_warning("tcp_option_missing"))

        iprule_mark = next(
            (r.get("fwmark") for r in data["routing"][node_id]["rules"] if r.get("fwmark")),
            None
        )
        iptables_mark = next(
            (r.get("mark") for r in data["routing"][node_id]["iptables"] if r.get("mark")),
            None
        )

        if iprule_mark != iptables_mark:
            warnings.append(get_warning("tcp_mark_mismatch"))

    return warnings
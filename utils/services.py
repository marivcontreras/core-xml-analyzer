def commands_text(data, node_id):
    """Script text of a node to scan for commands (ip addr, ip route, iptables...).

    The StaticRoute service comes first, followed by the text of every other
    service that is enabled on the node (e.g. DefaultRoute with a custom
    config). Configs of services that are not enabled are left out.
    """
    configs = data["services"].get(node_id, {})
    enabled = data["devices"].get(node_id, {}).get("services", [])

    names = ["StaticRoute"] + [name for name in enabled if name != "StaticRoute"]
    return "\n".join(configs[name] for name in names if configs.get(name))

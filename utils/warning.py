def add_warning(data, message, *, wtype="generic", scope="network",
                network=None, node=None, interface=None,
                code=None, details=None):

    warning = {
        "message": message,
        "type": wtype,
        "scope": scope,
    }

    if network:
        warning["network"] = network
    if node:
        warning["node"] = node
    if interface:
        warning["interface"] = interface
    if code:
        warning["code"] = code
    if details:
        warning["details"] = details

    data["warnings"].append(warning)
from pathlib import Path
import yaml

from utils.subjects import Subject

_current_config = None

def set_config(config):
    global _current_config
    _current_config = config

def get_config():
    return _current_config

def get_class_name():
    config = get_config()
    if config is None:
        raise ValueError("Configuration has not been loaded.")
    return config.get("class_name", None)

def get_max_prefixes_per_network():
    config = get_config()
    if config is None:
        raise ValueError("Configuration has not been loaded.")
    return config.get("max_prefixes_per_network", 2)

def load_config(filename: str):
    with open(Path("config") / filename, encoding="utf-8") as f:
        return yaml.safe_load(f)

def format_network_name(name):
    name = str(name)
    if "<>" in name:
        return name
    return name.lower().title()

def get_subjects():
    config = get_config()
    if config is None:
        raise ValueError("Configuration has not been loaded.")

    subjects = config.get("subjects", [])
    return [Subject.from_value(subject) for subject in subjects]


def has_subject(subject):
    """True if the given Subject is active for the current class."""
    return subject in get_subjects()


def get_ipv6_support():
    """True if the current class works with IPv6 (e.g. rdc2)."""
    config = get_config()
    if config is None:
        raise ValueError("Configuration has not been loaded.")
    return bool(config.get("ipv6_support", False))


def get_iptables_columns():
    config = get_config()
    if config is None:
        return []

    firewall = config.get("firewall", {})
    iptables_table = firewall.get("iptables_table", {})
    columns = iptables_table.get("columns")

    if columns:
        return list(columns)

    if config.get("class_name") == "rdc1":
        return ["chain", "src", "dst", "iif", "oif", "mark", "target"]

    return ["chain", "src", "dst", "iif", "oif", "protocol", "mark", "target"]


def get_network_names(networks):
    if isinstance(networks, dict):
        return [format_network_name(name) for name in networks]
    return [
        format_network_name(item if isinstance(item, str) else item.get("name"))
        for item in networks or []
        if (isinstance(item, str) or isinstance(item, dict))
        and (item if isinstance(item, str) else item.get("name"))
    ]

def get_network_mask_direct(networks, network_name):
    network_name = format_network_name(network_name)
    for network_group in networks.values():
        if isinstance(network_group, dict):
            matching_name = next(
                (name for name in network_group
                 if format_network_name(name) == network_name),
                None,
            )
            if matching_name is None:
                continue
            network_config = network_group[matching_name]
            if isinstance(network_config, list):
                network_config = network_config[0] if network_config else {}
        elif isinstance(network_group, list):
            network_config = next(
                (item for item in network_group
                 if isinstance(item, dict)
                 and format_network_name(item.get("name", "")) == network_name),
                None,
            )
        else:
            continue

        if isinstance(network_config, dict):
            return network_config.get("mask")

    return None

def get_network_mask(network_name):
    network_name = format_network_name(network_name)
    networks = get_config().get("networks", {})
    mask = get_network_mask_direct(networks, network_name)
    if mask is not None or "<>" not in network_name:
        return mask

    left, right = network_name.split("<>", 1)
    return get_network_mask_direct(networks, f"{right}<>{left}")


def get_network_last_octet(network_name, section="intranet_lan_networks"):
    network_name = format_network_name(network_name)
    networks = get_config().get("networks", {})
    
    intranet_networks = (networks.get("intranet_lan_networks", []) + networks.get("intranet_p2p_networks", []))

    for network in intranet_networks:
        if not isinstance(network, dict):
            continue

        if format_network_name(network.get("name", "")) != network_name:
            continue

        last_octet = network.get("last_octet")
        if last_octet is None:
            return None

        return int(last_octet)

    return None


def _with_reverse_p2p_networks(networks):
    expanded = get_network_names(networks)
    for network in expanded:
        if "<>" not in network:
            continue
        left, right = network.split("<>", 1)
        reverse = f"{right}<>{left}"
        if reverse not in expanded:
            expanded.append(reverse)
    return expanded

def is_intranet_network(network):
    network = format_network_name(network)
    networks = get_config().get("networks", {})
    intranet_networks = (
        get_network_names(networks.get("intranet_lan_networks", []))
        + _with_reverse_p2p_networks(networks.get("intranet_p2p_networks", []))
    )
    #print(f"Checking if network {network} is intranet. Intranet networks: {intranet_networks}")
    return network in intranet_networks

def is_internet_network(network):
    network = format_network_name(network)
    networks = get_config().get("networks", {})
    internet_networks = (
        get_network_names(networks.get("internet_networks", []))
        + _with_reverse_p2p_networks(networks.get("internet_p2p_networks", []))
    )
    #print(f"Checking if network {network} is internet. Internet networks: {internet_networks}")
    return network in internet_networks
from pathlib import Path
import yaml

_current_config = None

def set_config(config):
    global _current_config
    _current_config = config

def get_config():
    return _current_config

def load_config(filename: str):
    with open(Path("config") / filename, encoding="utf-8") as f:
        return yaml.safe_load(f)

def get_subjects():
    config = get_config()
    if config is None:
        raise ValueError("Configuration has not been loaded.")
    return config.get("subjects", [])

def _network_names(networks):
    if isinstance(networks, dict):
        return list(networks)
    return [
        item if isinstance(item, str) else item.get("name")
        for item in networks or []
        if isinstance(item, str) or isinstance(item, dict)
    ]

def _get_network_mask_direct(networks, network_name):
    for network_group in networks.values():
        if isinstance(network_group, dict):
            if network_name not in network_group:
                continue
            network_config = network_group[network_name]
            if isinstance(network_config, list):
                network_config = network_config[0] if network_config else {}
        elif isinstance(network_group, list):
            network_config = next(
                (item for item in network_group
                 if isinstance(item, dict) and item.get("name") == network_name),
                None,
            )
        else:
            continue

        if isinstance(network_config, dict):
            return network_config.get("mask")

    return None

def get_network_mask(network_name):
    networks = get_config().get("networks", {})
    mask = _get_network_mask_direct(networks, network_name)
    if mask is not None or "<>" not in network_name:
        return mask

    left, right = network_name.split("<>", 1)
    return _get_network_mask_direct(networks, f"{right}<>{left}")


def _with_reverse_p2p_networks(networks):
    expanded = _network_names(networks)
    for network in expanded:
        if "<>" not in network:
            continue
        left, right = network.split("<>", 1)
        reverse = f"{right}<>{left}"
        if reverse not in expanded:
            expanded.append(reverse)
    return expanded

def is_intranet_network(network):
    networks = get_config().get("networks", {})
    intranet_networks = (
        _network_names(networks.get("intranet_lan_networks", []))
        + _with_reverse_p2p_networks(networks.get("intranet_p2p_networks", []))
    )
    #print(f"Checking if network {network} is intranet. Intranet networks: {intranet_networks}")
    return network in intranet_networks

def is_internet_network(network):
    networks = get_config().get("networks", {})
    internet_networks = (
        _network_names(networks.get("internet_networks", []))
        + _with_reverse_p2p_networks(networks.get("internet_p2p_networks", []))
    )
    #print(f"Checking if network {network} is internet. Internet networks: {internet_networks}")
    return network in internet_networks
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

def _with_reverse_p2p_networks(networks):
    expanded = list(networks)
    for network in networks:
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
        networks.get("intranet_lan_networks", [])
        + _with_reverse_p2p_networks(networks.get("intranet_p2p_networks", []))
    )
    #print(f"Checking if network {network} is intranet. Intranet networks: {intranet_networks}")
    return network in intranet_networks

def is_internet_network(network):
    networks = get_config().get("networks", {})
    internet_networks = (
        networks.get("internet_networks", [])
        + _with_reverse_p2p_networks(networks.get("internet_p2p_networks", []))
    )
    #print(f"Checking if network {network} is internet. Internet networks: {internet_networks}")
    return network in internet_networks
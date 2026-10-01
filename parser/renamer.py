import ipaddress

from utils import config_helper


# All intranet networks live in a block whose first octet is 10.
_INTRANET_BLOCK = ipaddress.ip_network("10.0.0.0/8")


def _set_name(element, new_name, renamed):
    """Sets the name and remembers the original one (first rename wins)."""
    renamed.setdefault(element, element.get("name"))
    element.set("name", new_name)


def _network_of(iface):
    """ip_network of an <iface> element, or None if it has no valid ip4."""
    if iface is None or not iface.get("ip4") or not iface.get("ip4_mask"):
        return None
    try:
        return ipaddress.ip_network(f"{iface.get('ip4')}/{iface.get('ip4_mask')}", strict=False)
    except ValueError:
        return None


def _iface_ip(iface):
    return ipaddress.ip_address(iface.get("ip4"))


def _expected_l2_name(net, expected_by_key):
    """Config name whose (last_octet, mask) matches the network, if unique."""
    if net is None or net.version != 4 or not net.subnet_of(_INTRANET_BLOCK):
        return None
    key = (net.network_address.packed[-1], net.prefixlen)
    names = expected_by_key.get(key, [])
    return names[0] if len(names) == 1 else None


def _rename_l2_networks(root, networks_cfg, renamed):
    """Renames switches/wlans based on the last octet + mask of their network."""
    expected_by_key = {}
    for item in networks_cfg.get("intranet_lan_networks", []):
        if isinstance(item, dict) and item.get("last_octet") is not None and item.get("mask") is not None:
            key = (int(item["last_octet"]), int(item["mask"]))
            expected_by_key.setdefault(key, []).append(item["name"])

    section = root.find("networks")
    if section is None:
        return

    observed = {}  # l2 node id -> ip_network of its first addressed interface
    for link in root.findall("links/link"):
        for node_attr, iface_tag in (("node1", "iface1"), ("node2", "iface2")):
            net = _network_of(link.find(iface_tag))
            if net is None:
                continue
            other = link.get("node2" if node_attr == "node1" else "node1")
            observed.setdefault(other, net)

    fmt = config_helper.format_network_name
    renames = {}  # element -> new name
    for net_el in section.findall("network"):
        expected = _expected_l2_name(observed.get(net_el.get("id")), expected_by_key)
        if expected is not None and fmt(net_el.get("name")) != fmt(expected):
            renames[net_el] = expected

    # A network outside the intranet may share last octet + mask with a configured
    # one; never take a name that another (non renamed) node already holds.
    kept = {fmt(n.get("name")) for n in section.findall("network") if n not in renames}
    for net_el, expected in renames.items():
        if fmt(expected) not in kept:
            _set_name(net_el, expected, renamed)


def _rename_p2p_routers(root, networks_cfg, renamed):
    """Renames routers linked directly, using the p2p network 'A<>B' of the config.

    Matches the link by last octet + mask. When both router names are already
    the expected ones nothing changes; otherwise the router with the lower IP
    is named A and the other B.
    """
    devices = {d.get("id"): d for d in root.findall("devices/device") if d.get("type") == "router"}

    for item in networks_cfg.get("intranet_p2p_networks", []):
        if not isinstance(item, dict) or "<>" not in str(item.get("name")):
            continue
        if item.get("last_octet") is None or item.get("mask") is None:
            continue
        key = (int(item["last_octet"]), int(item["mask"]))
        left, right = item["name"].split("<>", 1)

        for link in root.findall("links/link"):
            d1, d2 = devices.get(link.get("node1")), devices.get(link.get("node2"))
            i1, i2 = link.find("iface1"), link.find("iface2")
            if d1 is None or d2 is None:
                continue
            n1, n2 = _network_of(i1), _network_of(i2)
            if n1 is None or n1 != n2 or n1.version != 4 or not n1.subnet_of(_INTRANET_BLOCK):
                continue
            if (n1.network_address.packed[-1], n1.prefixlen) != key:
                continue

            current = {d1.get("name"), d2.get("name")}
            if current == {left, right}:
                break
            lower, higher = (d1, d2) if _iface_ip(i1) < _iface_ip(i2) else (d2, d1)
            _set_name(lower, left, renamed)
            _set_name(higher, right, renamed)
            break


_PUBLIC_RANGE = ipaddress.ip_network("200.0.0.0/5")  # 200.0.0.0 - 207.255.255.255
_HOME_RANGE = ipaddress.ip_network("192.168.0.0/16")


def _rename_isp_and_r1(root, renamed):
    """ISP is the router attached only to 200.x networks; R1 the one attached to 192.168.x."""
    routers = {d.get("id"): d for d in root.findall("devices/device") if d.get("type") == "router"}

    nets = {rid: [] for rid in routers}
    for link in root.findall("links/link"):
        for node_attr, iface_tag in (("node1", "iface1"), ("node2", "iface2")):
            rid = link.get(node_attr)
            net = _network_of(link.find(iface_tag))
            if rid in nets and net is not None and net.version == 4:
                nets[rid].append(net)

    for rid, router_nets in nets.items():
        if not router_nets:
            continue
        if all(n.subnet_of(_PUBLIC_RANGE) for n in router_nets):
            _set_name(routers[rid], "ISP", renamed)
        elif any(n.subnet_of(_HOME_RANGE) for n in router_nets):
            _set_name(routers[rid], "R1", renamed)


def rename_nodes_by_last_octet(root):
    """Renames switches and routers whose name differs from the configuration.

    Controlled by the ``rename_nodes_by_last_octet`` flag in the config file.
    Must run on the XML tree before parsing. Returns a list of
    ``(old_name, new_name)`` for every node whose name actually changed.
    """
    if not config_helper.get_rename_nodes_by_last_octet():
        return []

    networks_cfg = config_helper.get_config().get("networks", {})
    renamed = {}  # element -> original name
    _rename_l2_networks(root, networks_cfg, renamed)
    _rename_isp_and_r1(root, renamed)
    _rename_p2p_routers(root, networks_cfg, renamed)

    return [(old, el.get("name")) for el, old in renamed.items() if old != el.get("name")]

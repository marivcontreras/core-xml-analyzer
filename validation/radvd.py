
from analyzer.prefixes import get_radvd_interfaces, get_staticroute_addresses
from utils.warning import add_warning


def validate_radvd_interfaces(data):
    for node_id, services in data["services"].items():
        if "radvd" not in services:
            continue

        node = data["devices"].get(node_id, {"name": f"node{node_id}"})
        node_name = node["name"]

        radvd_map = get_radvd_interfaces(node_id, data)
        addr_map = get_staticroute_addresses(node_id, data)
       
        for iface, prefixes in radvd_map.items():
            assigned_ips = addr_map.get(iface, [])

            if not assigned_ips:
                add_warning(
                    data,
                    f"{node_name}: La interfaz {iface} tiene configurado radvd pero no se encontraron direcciones asignadas correspondientes al bloque anunciado",
                    wtype="missing",
                    scope="interface",
                    node=node_name,
                    interface=iface,
                    code="radvd_without_ip"
                )
                continue

            for ip in assigned_ips:
                if not any(ip.ip in prefix for prefix in prefixes):
                    add_warning(
                        data,
                        f"{node_name}: La dirección {ip} en la interfaz {iface} no pertenece a los bloques anunciados",
                        wtype="invalid",
                        scope="interface",
                        node=node_name,
                        interface=iface,
                        code="ip_outside_radvd_prefix"
                    )

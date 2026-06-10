# Centralized warning messages resource file
# Maps warning codes to their messages, types, and metadata

WARNINGS = {
    # ================================================================
    # NETWORK VALIDATION WARNINGS
    # ================================================================

    "duplicated_prefix": {
        "message": "{net_name}: el prefijo {prefix} ya fue asignado a la red {other_network}",
        "type": "invalid",
        "scope": "network"
    },

    "ipv4_with_other_prefixes": {
        "message": "{net_name}: se asignaron direcciones adicionales en internet ({prefixes})",
        "type": "design",
        "scope": "network"
    },

    "invalid_prefixes": {
        "message": "{net_name}: prefijo invalido ({prefixes})",
        "type": "design",
        "scope": "network"
    },

    "too_many_prefixes": {
        "message": "{net_name}: se asignaron mas de 2 bloques de red ({prefixes})",
        "type": "design",
        "scope": "network"
    },

    "invalid_prefix_length": {
        "message": "{net_name}: prefijo {prefix} deberia ser /{expected}",
        "type": "invalid",
        "scope": "network"
    },

    "missing_site_prefix": {
        "message": "{net_name}: prefijo site faltante (existentes: {existing})",
        "type": "missing",
        "scope": "network"
    },

    "missing_global_prefix": {
        "message": "{net_name}: prefijo global faltante (existentes: {existing})",
        "type": "missing",
        "scope": "network"
    },

    "admin_with_global": {
        "message": "{net_name}: red admin no debería usar direcciones globales",
        "type": "design",
        "scope": "network"
    },

    "p2p_global_mismatch": {
        "message": "{net_name}: direcciones globales de distintos bloques ({global_a} - {global_b})",
        "type": "inconsistent",
        "scope": "link"
    },

    "p2p_site_mismatch": {
        "message": "{net_name}: direcciones site de distintos bloques ({site_a} - {site_b})",
        "type": "inconsistent",
        "scope": "link"
    },

    "p2p_missing_global": {
        "message": "{net_name}: {node_name} ({iface}) sin dirección global",
        "type": "inconsistent",
        "scope": "link"
    },

    "p2p_missing_site": {
        "message": "{net_name}: {node_name} ({iface}) sin dirección site",
        "type": "inconsistent",
        "scope": "link"
    },

    # ================================================================
    # NETWORK INFERENCE WARNINGS (analyzer/networks.py)
    # ================================================================

    "missing_ip_interface": {
        "message": "{node_name} no tiene una dirección IP en {interface_name} (red {net_name})",
        "type": "missing",
        "scope": "interface"
    },

    "missing_ip_p2p": {
        "message": "{node_name} no tiene una dirección IP en {interface_name} (p2p)",
        "type": "missing",
        "scope": "interface"
    },

    # ================================================================
    # IP COMMANDS VALIDATION WARNINGS
    # ================================================================

    "invalid_ip_command": {
        "message": "{node_name}: comando inválido → '{line}'",
        "type": "syntax",
        "scope": "node"
    },

    "interface_not_found": {
        "message": "{node_name}: interfaz {interface_name} no existe",
        "type": "invalid",
        "scope": "interface"
    },

    "invalid_prefix_length_ipv6": {
        "message": "{node_name}: máscara inválida en '{line}'",
        "type": "invalid",
        "scope": "interface"
    },

    "invalid_ipv4": {
        "message": "{node_name}: dirección IPv4 inválida en '{line}'",
        "type": "invalid",
        "scope": "interface"
    },

    "invalid_prefix_length_ipv4": {
        "message": "{node_name}: máscara inválida en '{line}'",
        "type": "invalid",
        "scope": "interface"
    },

    "invalid_ipv6": {
        "message": "{node_name}: dirección IPv6 inválida en '{line}'",
        "type": "invalid",
        "scope": "interface"
    },

    # ================================================================
    # RADVD VALIDATION WARNINGS
    # ================================================================

    "radvd_without_ip": {
        "message": "{node_name}: La interfaz {interface_name} tiene configurado radvd pero no se encontraron direcciones asignadas correspondientes al bloque anunciado",
        "type": "missing",
        "scope": "interface"
    },

    "ip_outside_radvd_prefix": {
        "message": "{node_name}: La dirección {ip} en la interfaz {interface_name} no pertenece a los bloques anunciados",
        "type": "invalid",
        "scope": "interface"
    },

    # ================================================================
    # ROUTING VALIDATION WARNINGS
    # ================================================================

    "missing_route": {
        "message": "Ruta faltante hacia '{route_name}'",
        "type": "error",
        "category": "routing"
    },

    "no_indirect_routes": {
        "message": "No se encontraron las rutas indirectas necesarias para alcanzar las redes publicas IPv4.",
        "type": "warning",
        "category": "routing"
    },

    "missing_isp_route": {
        "message": "No se encontró la ruta ISP hacia {route_name}",
        "type": "warning",
        "category": "isp"
    },

    "invalid_isp_route": {
        "message": "No se encontró una ruta ISP válida hacia {route_name}",
        "type": "warning",
        "category": "isp"
    },

    "invalid_field_error": {
        "message": "Error en campo {field} para {route_name}: esperado -> {expected}, actual -> {actual}",
        "type": "warning",
        "category": "isp"
    },

    "invalid_default_route": {
        "message": "Error de concepto: Ruta default invalida en {route}",
        "type": "warning",
        "category": "isp"
    },

    # ================================================================
    # TUNNEL VALIDATION WARNINGS
    # ================================================================

    "no_tunnel_configured": {
        "message": "No se encontró un túnel configurado en {router_name}",
        "type": "error",
        "category": "tunnels"
    },

    "invalid_tunnel": {
        "message": "Túnel invalido con local {local_ip} y remote {remote_ip} en {router_name}.",
        "type": "error",
        "category": "tunnels"
    },

    "tunnel_invalid_local": {
        "message": "La dirección local {local_ip} del túnel configurado en {router_name} no existe en el {router_name} en la interfaz {expected_interface}. Se resolvió como {resolved_local}",
        "type": "warning",
        "category": "tunnels"
    },

    "tunnel_invalid_remote": {
        "message": "La dirección remota {remote_ip} del túnel configurado en {router_name} no existe en el {remote_router} en la interfaz {expected_interface}. Se resolvió como {resolved_remote}",
        "type": "warning",
        "category": "tunnels"
    },

    # ================================================================
    # ROUTING MATRIX VALIDATION WARNINGS (from warnings.append)
    # ================================================================

    "unreachable_network": {
        "message": "{prefix_type}: No se pueden alcanzar las redes {route_name} desde {router_name}",
        "type": "error",
        "category": "routing"
    },

    "missing_route_additional_table": {
        "message": "{prefix_type}: No se encontraron las rutas hacia las redes {route_name} en la tabla adicional esperada para {table} en el router {router_name}. ",
        "type": "warning",
        "category": "routing"
    },

    "invalid_route_field": {
        "message": "La ruta hacia la red {prefix_type} {route_name} tiene un valor inválido en el campo {field}. Esperado: {expected}. Actual: {actual}.",
        "type": "error",
        "category": "routing"
    },

    "invalid_route_field_minimization": {
        "message": "La ruta hacia la red {prefix_type} {route_name} no está siendo minimizada por default. Destino esperado: {expected}. Actual: {actual}.",
        "type": "warning",
        "category": "routing"
    },

    "invalid_route_field_minimization_policy": {
        "message": "La ruta hacia la red {prefix_type} {route_name} no está siendo minimizada por default en la tabla {table}. Destino esperado: {expected}. Actual: {actual}.",
        "type": "warning",
        "category": "routing"
    },


    "invalid_route_field_default": {
        "message": "Los paquetes dirigidos hacia la red {prefix_type} {route_name} están siendo direccionados incorrectamente a través de la entrada por default. Campo via esperado: {expected}. ",
        "type": "error",
        "category": "routing"
    },

    "invalid_route_field_via_info": {
        "message": "La ruta hacia la red {prefix_type} {route_name} tiene un valor inválido en el campo {field}. Esperado: {expected}. Actual: {actual}.",
        "type": "error",
        "category": "routing"
    },

    "invalid_route_field_via_info_none": {
        "message": "La ruta hacia la red {prefix_type} {route_name} tiene un valor inválido en el campo {field}. Esperado: {expected}. Actual: la dirección IP es inválida o no está asignada.",
        "type": "error",
        "category": "routing"
    },

    # ================================================================
    # POLICY INFERENCE WARNINGS (from analyzer/policy.py)
    # ================================================================

    "tcp_approach_iptables": {
        "message": "Se detectaron reglas de iptables para marcar paquetes TCP",
        "type": "information",
        "category": "policy"
    },

    "tcp_option_missing": {
        "message": "No se detectó la opción tcp en el comando iptables",
        "type": "error",
        "category": "policy"
    },

    "tcp_mark_mismatch": {
        "message": "El valor de fwmark en ip rule no coincide con el valor configurado en iptables para marcar tráfico TCP",
        "type": "error",
        "category": "policy"
    },

    "tcp_approach_iprule": {
        "message": "Se detectó una regla ip rule con la opción ipproto para TCP",
        "type": "information",
        "category": "policy"
    },
}

def get_warning(code):
    """
    Retrieve a warning template by code.

    Args:
        code: Warning code key

    Returns:
        Warning template dict or None if code not found
    """
    return WARNINGS.get(code)

def get_warning_message(code, **kwargs):
    """
    Retrieve and format a warning message by code.

    Args:
        code: Warning code key
        **kwargs: Format parameters for the message template

    Returns:
        Formatted message string or None if code not found
    """
    if code not in WARNINGS:
        return None

    template = WARNINGS[code].get("message", "")
    try:
        return template.format(**kwargs)
    except KeyError as e:
        # Return template with unfilled placeholders if kwargs are incomplete
        return template

def get_warning_type(code):
    """Get the type of a warning by code."""
    return WARNINGS.get(code, {}).get("type", "generic")

def get_warning_scope(code):
    """Get the scope of a warning by code."""
    return WARNINGS.get(code, {}).get("scope", "network")

def get_warning_category(code):
    """Get the category of a routing warning by code."""
    return WARNINGS.get(code, {}).get("category")

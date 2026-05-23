from analyzer.prefixes import get_staticroute_interface_addresses
from parser.devices import get_node, get_node_id
from parser.routing import build_routing_matrix, resolve_ip_owner
from report.formatters import format_route, format_via_info, reverse_route_name
from utils.ip import PREFIX_TYPE
from utils.warning import add_routing_warning
from validation.routingHelper import ANY, ISP_EXPECTED

# -------------------------------------------------------------
# Creates a validation table and a list of warnings related to routing configuration.
# Validations include:
# - Missing or wrong parameters (e.g. via_info mismatch, wrong table, etc)
# - Missing routes
# -------------------------------------------------------------
def validate_routing_matrix(interpreted_matrix, expected_matrix):
    warnings = []
    validation_table = {}

    for router_name, expected_routes in expected_matrix.items():

        validation_table.setdefault(router_name, {})

        interpreted_routes = interpreted_matrix.get(router_name, {})
        for route_name, expected in expected_routes.items():

            interpreted = interpreted_routes.get(route_name)

            # --------------------------------------------------
            # reverse p2p route support
            # --------------------------------------------------

            if interpreted is None and "<>" in route_name:
                reversed_name = reverse_route_name(route_name)
                interpreted = interpreted_routes.get(reversed_name)

            # --------------------------------------------------
            # validation structure
            # --------------------------------------------------

            route_result = {
                "exists": True,
                "valid": False,

                # render-friendly summary
                "field_validation": {},

                # detailed matching info
                "matched_routes": [],
                "missing_expected_routes": [],
                "extra_routes": []
            }

            validation_table[router_name][route_name] = route_result

            # --------------------------------------------------
            # Missing route entirely
            # --------------------------------------------------

            if interpreted is None:

                warnings.append({
                    "router": router_name,
                    "route": route_name,
                    "severity": "error",
                    "message": f"Ruta faltante hacia '{route_name}'"
                })

                route_result["exists"] = False
                continue

            # --------------------------------------------------
            # normalize single dict -> list
            # backward compatibility
            # --------------------------------------------------

            if not isinstance(interpreted, list):
                interpreted = [interpreted]

            # --------------------------------------------------
            # normalize expected
            # --------------------------------------------------

            expected_routes_list = expected

            if not isinstance(expected_routes_list, list):
                expected_routes_list = [expected_routes_list]

            matched_interpreted_indexes = set()

            # --------------------------------------------------
            # validate each expected route
            # --------------------------------------------------

            for expected_route in expected_routes_list:                
                matched = False
                best_candidate = None
                best_candidate_score = -1

                for idx, interpreted_route in enumerate(interpreted):

                    # already consumed by another expected route
                    if idx in matched_interpreted_indexes:
                        continue
                    
                    # --------------------------------------------------
                    # compare only routes with same intent
                    # --------------------------------------------------

                    expected_prefix_type = expected_route.get("prefix_type")
                    interpreted_prefix_type = interpreted_route.get("prefix_type")

                    if (expected_prefix_type is not None and interpreted_prefix_type is not None and interpreted_prefix_type != expected_prefix_type):
                        continue
                
                    expected_is_policy = expected_route.get("is_policy")
                    interpreted_is_policy = interpreted_route.get("is_policy")

                    if (expected_is_policy is not ANY and interpreted_is_policy != expected_is_policy):
                        continue

                    field_results = {}

                    valid_fields = 0
                    invalid_fields = 0

                    for field_name, expected_value in expected_route.items():

                        interpreted_value = interpreted_route.get(field_name)

                        field_result = validate_route_field(field_name, interpreted_value, expected_value)

                        field_results[field_name] = field_result

                        if field_result["valid"]:
                            valid_fields += 1
                        else:
                            invalid_fields += 1

                    score = valid_fields - invalid_fields

                    if score > best_candidate_score:

                        best_candidate_score = score

                        best_candidate = {
                            "interpreted_index": idx,
                            "interpreted_route": interpreted_route,
                            "field_results": field_results,
                        }

                        best_candidate["interpreted_route"]["_field_validation"] = dict(field_results)

                    # ----------------------------------------------
                    # full match
                    # ----------------------------------------------

                    if invalid_fields == 0:

                        matched = True

                        matched_interpreted_indexes.add(idx)
                        interpreted_route["_field_validation"] = field_results
                        route_result["matched_routes"].append({
                            "expected": expected_route,
                            "actual": interpreted_route,
                            "fields": field_results,
                            "valid": True
                        })
                        break

                    # --------------------------------------------------
                    # mirror via_info validation into via
                    # so both fields highlight together
                    # --------------------------------------------------

                    via_info_validation = best_candidate["interpreted_route"]["_field_validation"].get("via_info")

                    if via_info_validation is not None and not via_info_validation["valid"]:
                        best_candidate["interpreted_route"]["_field_validation"]["via"] = {
                            "valid": via_info_validation["valid"],
                            "expected": via_info_validation["expected"],
                            "actual": via_info_validation["actual"]
                        }              

                # --------------------------------------------------
                # no valid interpreted route matched
                # --------------------------------------------------

                if not matched:

                    route_result["missing_expected_routes"].append({
                        "expected": expected_route,
                        "best_candidate": best_candidate
                    })

                    warnings.append({
                        "router": router_name,
                        "route": route_name,
                        "severity": "error",
                        "message": (
                            f"No se puede alcanzar la red {expected_route.get("prefix_type")} {route_name} desde {router_name}" 
                        )
                    })

                    if best_candidate:

                        for field_name, field_result in best_candidate["field_results"].items():

                            if not field_result["valid"]:

                                warnings.append({
                                    "router": router_name,
                                    "route": route_name,
                                    "field": field_name,
                                    "severity": "error",
                                    "expected": field_result["expected"],
                                    "actual": field_result["actual"],
                                    "message": build_invalid_field_warning(
                                        router_name,
                                        route_name,
                                        field_name,
                                        field_result["expected"],
                                        field_result["actual"]
                                    )
                                })

            # --------------------------------------------------
            # final validity
            # --------------------------------------------------

            route_result["valid"] = (len(route_result["missing_expected_routes"]) == 0)

        # ------------------------------------------------------
        # detect totally unexpected networks
        # ------------------------------------------------------

        #for route_name in interpreted_routes.keys():

        #    if (route_name not in expected_routes and reverse_route_name(route_name) not in expected_routes):
        #        warnings.append({
        #            "router": router_name,
        #            "route": route_name,
        #            "severity": "warning",
        #            "message": f"Ruta adicional no esperada hacia {route_name}"
        #        })

        from collections import defaultdict

        grouped_warnings = defaultdict(
            lambda: defaultdict(list)
        )

        for warning in warnings:

            router = warning.get("router", "Unknown")
            route = warning.get("route", "Unknown")

            grouped_warnings[router][route].append(warning)

    return {
        "warnings": warnings,
        "grouped_warnings": grouped_warnings,
        "validation_table": validation_table
    }

# -------------------------------------------------------------
# Propagate routing validation warnings into the main routing data structure 
# for easier access when rendering the report.
# -------------------------------------------------------------
def propagate_routing_warnings(data, validation_result):
    routing_data = data.get("routing", {})
    grouped_warnings = validation_result.get(
        "grouped_warnings",
        {}
    )

    for router, route_warnings in grouped_warnings.items():
        print(f"Propagando warning para {router}: {route_warnings}")
        node_id = get_node_id(data, router)
        router_data = routing_data.get(node_id)

        if not router_data:
            continue

        router_data.setdefault("warnings", [])

        existing_messages = {
            warn
            for warn in router_data["warnings"]
        }

        for net, warnings in route_warnings.items():

            for warning in warnings:
                print(f"Propagando warning para {router}: {warning}")
                message = warning.get("message")

                if message in existing_messages:
                    continue

                add_routing_warning(
                    router_data,
                    "routing",
                    warning.get("severity","warning"),
                    message
                )
                
                existing_messages.add(message)

# -------------------------------------------------------------
# Validate a single field of a route, supporting special rules for certain fields  
# and generic allowed values validation.
# -------------------------------------------------------------
def validate_route_field(field_name, actual, expected):
    result = {
        "valid": True,
        "expected": expected,
        "actual": actual,
        "highlight": None
    }

    # Ignore
    if expected == "__ANY__":
        return result

    # Auto-generated/runtime
    if expected == "__AUTO__":
        return result

    if field_name == "table":
        if actual != expected and (expected != "main"):
            result["valid"] = True
            result["highlight"] = None

        return result

    if field_name == "type":
        if isinstance(expected, list) and actual in expected:
            result["valid"] = True
            result["highlight"] = None

        return result
    
    # Direct comparison
    if not isinstance(expected, list):
        if actual != expected:
            result["valid"] = False
            result["highlight"] = "red"

        return result

    # List validation
    if field_name == "via_info":
        if not match_via_info(actual, expected):
            result["valid"] = False
            result["highlight"] = "red"

        return result
    
    # Generic allowed values
    if actual not in expected:
        result["valid"] = False
        result["highlight"] = "red"

    return result

# -------------------------------------------------------------
# Validate the via_info field against a list of posible destination defined by node and interface.
# -------------------------------------------------------------
def match_via_info(actual, expected_options):
    if actual is None:
        return False

    for expected in expected_options:
        same_node = actual.get("node") == expected.get("node")
        same_interface = actual.get("interface") == expected.get("interface")

        if same_node and same_interface:
            return True

    return False

# -------------------------------------------------------------
# Creates a human-friendly warning message for an invalid field, 
# with special formatting for certain fields like via_info.
# -------------------------------------------------------------
def build_invalid_field_warning(router, route, field, expected, actual):
    if field == "via_info":
        if (actual is not None):
            return (
                f"[{router}] La ruta hacia la red {route} tiene un valor inválido en el campo {field}. "
                f"Posibles: {format_via_info(expected)}. Actual: {format_via_info(actual)}"
            )
        else:
            return (
                f"[{router}] La ruta hacia la red {route} tiene un valor inválido en el campo {field}. "
                f"Posibles: {format_via_info(expected)}. Actual: la dirección IP es inválida o no está asignada."
            )

    return (
        f"[{router}] La ruta hacia la red {route} tiene un valor inválido en el campo {field}. "
        f"Esperado: {expected}. Actual: {actual}"
    )

def validate_isp_routes(data):
    routing_data = data["routing"]
    matrix = build_routing_matrix(data, intranet=False)

    #print(f"Matriz de rutas interpretada para validación ISP: {matrix}")

    for router_name, expected_routes in ISP_EXPECTED.items():

        node_id = get_node_id(data, router_name)

        if node_id is None:
            continue

        router_data = routing_data.get(node_id)

        if router_data is None:
            continue

        interpreted_router_routes = matrix.get(router_name, {})
        print(f"Validando rutas {interpreted_router_routes} para {router_name}")   
        # --------------------------------------------------
        # indirect routes existence
        # --------------------------------------------------

        indirect_routes = []

        for routes in interpreted_router_routes.values():
            
            if not isinstance(routes, list):
                routes = [routes]

            for route in routes:
                if (route is None):
                    continue

                if (route["type"] == "IND" and route["via"] is not None):
                    indirect_routes.append(route)

        if not indirect_routes:

            add_routing_warning(
                router_data,
                "isp",
                "warning",
                (
                    "No se encontraron las rutas indirectas "
                    "necesarias para alcanzar las redes publicas IPv4."
                )
            )

        # --------------------------------------------------
        # validate expected ISP routes
        # --------------------------------------------------

        for route_name, expected in expected_routes.items():

            interpreted = interpreted_router_routes.get(route_name)

            # ----------------------------------------------
            # reverse p2p support
            # ----------------------------------------------

            if interpreted is None and "<>" in route_name:

                reversed_name = reverse_route_name(route_name)

                interpreted = interpreted_router_routes.get(reversed_name)

            if interpreted is None:

                add_routing_warning(
                    router_data,
                    "isp",
                    "warning",
                    (
                        f"No se encontró la ruta ISP "
                        f"hacia {route_name}"
                    )
                )

                continue

            # ----------------------------------------------
            # normalize
            # ----------------------------------------------

            expected_routes_list = expected

            if not isinstance(expected_routes_list, list):
                expected_routes_list = [expected_routes_list]

            if not isinstance(interpreted, list):
                interpreted = [interpreted]

            matched = False
            best_errors = []

            # ----------------------------------------------
            # validate
            # ----------------------------------------------

            for expected_route in expected_routes_list:

                for interpreted_route in interpreted:

                    field_errors = []

                    # --------------------------------------
                    # normal field validation
                    # --------------------------------------

                    for field_name, expected_value in expected_route.items():

                        interpreted_value = interpreted_route.get(field_name)

                        field_result = validate_route_field(
                            field_name,
                            interpreted_value,
                            expected_value
                        )

                        if not field_result["valid"]:

                            field_errors.append({
                                "field": field_name,
                                "expected": field_result["expected"],
                                "actual": field_result["actual"]
                            })

                    # --------------------------------------
                    # explicit via ownership validation
                    # --------------------------------------

                    via_ip = interpreted_route.get("via")

                    if via_ip:

                        resolved_owner = resolve_ip_owner(via_ip, data)

                        expected_vias = expected_route.get("via_info", [])

                        via_valid = False

                        for expected_via in expected_vias:

                            if (
                                resolved_owner.get("node") == expected_via.get("node")
                                and resolved_owner.get("interface") == expected_via.get("interface")
                            ):
                                via_valid = True
                                break

                        if not via_valid:

                            field_errors.append({
                                "field": "via",
                                "expected": (
                                    ", ".join(
                                        format_via_info(v)
                                        for v in expected_vias
                                    )
                                ),
                                "actual": format_via_info(resolved_owner)
                            })

                    # --------------------------------------
                    # full match
                    # --------------------------------------

                    if not field_errors:

                        matched = True
                        break

                    # --------------------------------------
                    # keep best candidate
                    # --------------------------------------

                    if (
                        not best_errors
                        or len(field_errors) < len(best_errors)
                    ):
                        best_errors = field_errors

                if matched:
                    break

            # --------------------------------------------------
            # warnings
            # --------------------------------------------------

            if not matched:

                add_routing_warning(
                    router_data,
                    "isp",
                    "warning",
                    (
                        f"No se encontró una ruta ISP válida "
                        f"hacia {route_name}"
                    )
                )

                for error in best_errors:

                    add_routing_warning(
                        router_data,
                        "isp",
                        "warning",
                        (
                            f"Error en campo {error['field']} "
                            f"para {route_name}: "
                            f"esperado -> {error['expected']}, "
                            f"actual -> {error['actual']}"
                        )
                    )

        # --------------------------------------------------
        # invalid default routes
        # --------------------------------------------------

        default_routes = []

        for routes in interpreted_router_routes.values():

            if not isinstance(routes, list):
                routes = [routes]

            for route in routes:
                if (route is None):
                    continue
                if route.get("dst") == PREFIX_TYPE["default"]:
                    default_routes.append(route)

        for route in default_routes:

            add_routing_warning(
                router_data,
                "isp",
                "warning",
                (
                    f"Error de concepto: "
                    f"Ruta default invalida en "
                    f"{format_route(route)}"
                )
            )

def validate_tunnels(data):

    expected_tunnels = {
        "R2": {
            "remote_router": "R-Casa",
            "remote_interface": "eth0",
            "local_interface": "eth2"
        },

        "R-Casa": {
            "remote_router": "R2",
            "remote_interface": "eth2",
            "local_interface": "eth0"
        }
    }

    for router_name, expected in expected_tunnels.items():

        node_id = get_node_id(data, router_name)

        if node_id is None:
            continue

        routing = data["routing"].get(node_id)

        if routing is None:
            continue

        tunnels = routing.get("tunnels", [])

        if not tunnels:

            add_routing_warning(
                routing,
                "tunnels",
                "error",
                (f"No se encontró un túnel configurado en {router_name}")
            )

            continue

        expected_remote_router = expected["remote_router"]
        expected_remote_interface = expected["remote_interface"]
        expected_local_interface = expected["local_interface"]

        matched = False

        for tunnel in tunnels:

            local_ip = tunnel.get("local")
            remote_ip = tunnel.get("remote")

            local_owner = resolve_ip_owner(local_ip, data)
            
            remote_owner = resolve_ip_owner(remote_ip, data)
            local_valid = (local_owner.get("node") == router_name and local_owner.get("interface") == expected_local_interface)            
            remote_valid = (remote_owner.get("node") == expected_remote_router and remote_owner.get("interface") == expected_remote_interface)
            if not local_valid or not remote_valid:
                add_routing_warning(
                    routing,
                    "tunnels",
                    "error",
                    (
                        f"Túnel invalido con local {local_ip} y remote {remote_ip} en {router_name}."
                    )
                )
            
            if not local_valid:
                add_routing_warning(
                    routing,
                    "tunnels",
                    "warning",
                    (   f"La dirección local {local_ip} del túnel configurado en {router_name}"
                        f" no existe en el {router_name} en la interfaz {expected_local_interface}. "
                        f"Se resolvió como {format_via_info(local_owner)}"
                    )
                )
            elif not remote_valid:
                add_routing_warning(
                    routing,
                    "tunnels",
                    "warning",
                    (
                        f"La dirección remota {remote_ip} del túnel configurado en {router_name} "
                        f"no existe en el {expected_remote_router} en la interfaz {expected_remote_interface}."
                        f"Se resolvió como {format_via_info(remote_owner)}"
                    )
                )
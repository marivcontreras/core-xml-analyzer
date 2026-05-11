from report.formatters import reverse_route_name
from validation.routingHelper import ANY

def validate_routing_matrix(interpreted_matrix, expected_matrix):
    warnings = []
    validation_table = {}

    for router_name, expected_routes in expected_matrix.items():

        validation_table.setdefault(router_name, {})

        interpreted_routes = interpreted_matrix.get(router_name, {})

        #print(
        #    f"Validating {router_name}: "
        #    f"interpreted_routes={interpreted_routes.keys()} "
        #    f"expected_routes={expected_routes.keys()}"
        #)

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
            # validation accumulators
            # --------------------------------------------------

            aggregated_field_validation = {}

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

                    if (
                        expected_prefix_type is not None and
                        interpreted_prefix_type != expected_prefix_type
                    ):
                        continue

                    expected_is_policy = expected_route.get("is_policy")
                    interpreted_is_policy = interpreted_route.get("is_policy")

                    if (
                        expected_is_policy is not ANY and
                        interpreted_is_policy != expected_is_policy
                    ):
                        continue

                    field_results = {}

                    valid_fields = 0
                    invalid_fields = 0

                    for field_name, expected_value in expected_route.items():

                        interpreted_value = interpreted_route.get(field_name)

                        field_result = validate_route_field(field_name, interpreted_value, expected_value)

                        field_results[field_name] = field_result

                        # ------------------------------------------
                        # aggregate render validation
                        # ------------------------------------------

                        current = aggregated_field_validation.get(field_name)

                        if current is None:
                            aggregated_field_validation[field_name] = {
                                "valid": field_result["valid"],
                                "expected": field_result["expected"],
                                "actual": field_result["actual"]
                            }

                        elif not field_result["valid"]:
                            aggregated_field_validation[field_name] = {
                                "valid": False,
                                "expected": field_result["expected"],
                                "actual": field_result["actual"]
                            }

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
                            "field_results": field_results
                        }

                    # ----------------------------------------------
                    # full match
                    # ----------------------------------------------

                    if invalid_fields == 0:

                        matched = True

                        matched_interpreted_indexes.add(idx)

                        route_result["matched_routes"].append({
                            "expected": expected_route,
                            "actual": interpreted_route,
                            "fields": field_results,
                            "valid": True
                        })

                        break

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
                            f"No se encontró una ruta válida hacia "
                            f"'{route_name}'"
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
                                    "message": build_warning_message(
                                        router_name,
                                        route_name,
                                        field_name,
                                        field_result["expected"],
                                        field_result["actual"]
                                    )
                                })

            # --------------------------------------------------
            # extra interpreted routes
            # --------------------------------------------------

            for idx, interpreted_route in enumerate(interpreted):

                if idx not in matched_interpreted_indexes:

                    route_result["extra_routes"].append(
                        interpreted_route
                    )

                    if (interpreted_route.get('table') == "main"):
                        warnings.append({
                            "router": router_name,
                            "route": route_name,
                            "severity": "warning",
                            "message": (
                                f"Ruta adicional en tabla main: {interpreted_route}"
                            )
                        })
                    else:
                        warnings.append({
                            "router": router_name,
                            "route": route_name,
                            "severity": "warning",
                            "message": (
                                f"Ruta hacia red '{route_name}' en tabla "
                                f"{interpreted_route.get('table')}"
                            )
                        })

            # --------------------------------------------------
            # final validity
            # --------------------------------------------------

            route_result["valid"] = (
                len(route_result["missing_expected_routes"]) == 0
            )

            route_result["field_validation"] = (
                aggregated_field_validation
            )

        # ------------------------------------------------------
        # detect totally unexpected networks
        # ------------------------------------------------------

        for route_name in interpreted_routes.keys():

            if (route_name not in expected_routes and reverse_route_name(route_name) not in expected_routes):
                warnings.append({
                    "router": router_name,
                    "route": route_name,
                    "severity": "warning",
                    "message": f"Ruta adicional no esperada hacia '{route_name}'"
                })

    return {
        "warnings": warnings,
        "validation_table": validation_table
    }

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

def match_via_info(actual, expected_options):
    if actual is None:
        return False

    for expected in expected_options:
        same_node = actual.get("node") == expected.get("node")
        same_interface = actual.get("interface") == expected.get("interface")

        if same_node and same_interface:
            return True

    return False


def build_warning_message(router, route, field, expected, actual):
    return (
        f"[{router}] La ruta '{route}' tiene un valor inválido para el campo '{field}'. "
        f"Esperado: {expected} | Actual: {actual}"
    )
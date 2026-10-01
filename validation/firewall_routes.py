import ipaddress

from utils.firewall_config import get_expected_routes
from validation.firewall_validation import make_warn, norm, resolve_value


def canonical_dst(dst):
    """Comparable form of a route destination (default == 0.0.0.0/0, host == host/32)."""
    if dst is None:
        return None
    if dst == "default":
        return "default"
    value = norm(dst)
    return "default" if value == "0.0.0.0/0" else value


def overlapping(a, b):
    try:
        return ipaddress.ip_network(a, strict=False).overlaps(ipaddress.ip_network(b, strict=False))
    except (ValueError, TypeError):
        return False


def resolve_route(spec, data, node_id):
    """Resolve the {dst, via, dev} spec of an expected route to (values, notes).

    dst     : "default", a literal, or {network: X} / {host: H, network: X}
    via     : {host: H, network: X}   address of device H in network X
    dev     : {network: X}            interface of the device in network X
    Absent keys are not compared.
    """
    values, notes = {}, {}
    for key in ("dst", "via", "dev"):
        value = spec.get(key)
        if isinstance(value, dict):
            value, notes[key] = resolve_value("oif" if key == "dev" else key, value, data, node_id)
        values[key] = value
    return values, notes


def format_route(values, notes=None):
    parts = ["ip route add", str(values["dst"])]
    if values.get("via"):
        parts += ["via", str(values["via"])]
    if values.get("dev"):
        parts += ["dev", str(values["dev"])]
    text = " ".join(parts)
    details = [f"{key}: {note}" for key, note in (notes or {}).items()]
    return f"{text}  ({'; '.join(details)})" if details else text


def route_score(expected, route):
    """How many of via/dev of a found route equal the expected ones."""
    score = 0
    if expected.get("via") and norm(route["via"]) == norm(expected["via"]):
        score += 1
    if expected.get("dev") and route["dev"] == expected["dev"]:
        score += 1
    return score


def find_route(expected, routes):
    """The found route that stands for the expected one, or None.

    A route with the same destination wins. Otherwise a route that overlaps it
    (e.g. a /24 block instead of the host's IP) is taken as the same route with
    a wrong destination. A default route never stands for a specific one.
    """
    wanted = canonical_dst(expected["dst"])
    exact = [r for r in routes if canonical_dst(r["dst"]) == wanted]
    if exact:
        return max(exact, key=lambda r: route_score(expected, r))
    if wanted == "default":
        return None
    near = [r for r in routes if canonical_dst(r["dst"]) != "default" and overlapping(r["dst"], expected["dst"])]
    return max(near, key=lambda r: route_score(expected, r)) if near else None


def validate_consigna_routes(data):
    """Compare the expected routes of each consigna with the ones found on the router.

    Stores the result in data["firewall"]["routes"]: one entry per router with
    expected routes (resources/<class>/firewall.yaml -> routes), each row holding
    the found route (if any) and its problems.
    """
    entries = []

    for name, expected_list in get_expected_routes().items():
        node_id = next((i for i, d in data["devices"].items() if d["name"] == name), None)
        if node_id is None:
            continue

        routes = [r for r in data["routing"].get(node_id, {}).get("routes", [])
                  if r["table"] == "main" and r["type"] == "unicast"]
        warnings = []
        warn = make_warn(name, warnings, category="routes")
        rows = []

        for spec in expected_list:
            consigna = spec.get("consigna") or "-"
            expected, notes = resolve_route(spec, data, node_id)
            command = format_route(expected, notes)
            found = find_route(expected, routes)
            row = {"consigna": spec.get("consigna"), "expected": command,
                   "found_id": None, "found": None, "problems": []}

            if found is None:
                row["problems"].append(warn("missing_consigna_route", consigna=consigna, expected=command))
            else:
                row["found_id"] = found["id"]
                row["found"] = format_route(found)

                if canonical_dst(found["dst"]) != canonical_dst(expected["dst"]):
                    hint = ""
                    if overlapping(found["dst"], expected["dst"]) and "/" not in str(expected["dst"]):
                        hint = " (se espera la ruta hacia la IP y no hacia todo el bloque)"
                    row["problems"].append(warn(
                        "consigna_route_wrong_dst", consigna=consigna,
                        expected_value=expected["dst"], actual=found["dst"], hint=hint))

                if expected.get("via") and norm(found["via"]) != norm(expected["via"]):
                    row["problems"].append(warn(
                        "consigna_route_wrong_via", consigna=consigna, dst=found["dst"],
                        expected_value=expected["via"], actual=found["via"] or "ninguno"))

                if expected.get("dev") and found["dev"] != expected["dev"]:
                    row["problems"].append(warn(
                        "consigna_route_wrong_dev", consigna=consigna, dst=found["dst"],
                        expected_value=expected["dev"], actual=found["dev"] or "ninguna"))

            rows.append(row)

        entries.append({"router": name, "rows": rows, "warnings": warnings})

    data["firewall"]["routes"] = entries

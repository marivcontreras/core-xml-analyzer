from utils.firewall_config import get_firewall_sections
from validation.firewall_validation import interpret_command, is_masquerade


def consigna_letter(consigna):
    """Letter of a consigna label: "G [!wlan-Inv > PC Admin]" -> "G"."""
    return consigna.split()[0].upper() if consigna else ""


def default_sections(entries):
    """One section per device when the class does not define `sections`."""
    return [{"title": name, "consignas": None, "firewall": [name], "routing": []} for name in entries]


def section_entry(entry, letters):
    """The part of a device entry that belongs to the given consignas
    (all of it when letters is None). Command numbers (N°) are kept."""
    def belongs(consigna):
        return letters is None or consigna_letter(consigna) in letters

    return {
        "router": entry["router"],
        "commands": [c for c in entry["commands"] if c["consigna"] and belongs(c["consigna"])],
        "rows": [r for r in entry["rows"] if belongs(r["consigna"])],
        "unevaluated": [],
        "unevaluated_n": {},
        "policy_errors": entry.get("policy_errors", {}),
    }


def unevaluated_numbers(entry, commands):
    """Order number (N°) of each command no consigna claimed, the same one the
    device's preview of commands gives it (None if the device has no such number)."""
    numbers = {}
    for c in (entry or {}).get("commands", []):
        numbers.setdefault(c["command"], c["n"])
    # Not in the preview (e.g. another table): position among the unclaimed ones.
    return {command: numbers.get(command) or i + 1 for i, command in enumerate(commands)}


def build_firewall_sections(data):
    """Group the filters analysis by consigna, as set in resources/<class>/firewall.yaml.

    Stores in data["firewall_sections"]:
      sections: one per group of consignas, with the expected commands of its
                devices (firewall), the commands of those consignas found on
                other devices (misplaced) and the routes of the devices whose
                routing it depends on (routing).
      others:   iptables commands that were not evaluated for any consigna.
    """
    entries = {e["router"]: e for e in data["firewall"]["filters"]}
    route_entries = {e["router"]: e for e in data["firewall"]["routes"]}
    node_ids = {d["name"]: node_id for node_id, d in data["devices"].items()}
    specs = get_firewall_sections() or default_sections(entries)

    # Commands that no consigna claimed (MASQUERADE has its own section).
    claimed = {(entry["router"], c["command"])
               for entry in entries.values() for c in entry["commands"] if c["consigna"]}
    unevaluated = {}
    for node_id, device in data["devices"].items():
        if device.get("type") != "router":
            continue
        commands = [r["command"] for r in data["routing"].get(node_id, {}).get("iptables", [])
                    if not is_masquerade(r) and (device["name"], r["command"]) not in claimed]
        if commands:
            unevaluated[device["name"]] = commands

    # Reading of the options of every command, for the ones no consigna claims.
    interpretations = {
        (device["name"], r["command"]): interpret_command(data, node_id, r)
        for node_id, device in data["devices"].items() if device.get("type") == "router"
        for r in data["routing"].get(node_id, {}).get("iptables", [])
    }

    sections = []
    shown = set()
    for spec in specs:
        letters = {str(c).upper() for c in spec["consignas"]} if spec.get("consignas") else None
        firewall = [section_entry(entries[name], letters) for name in spec.get("firewall", []) if name in entries]
        for entry in firewall:
            entry["interpretations"] = {c: interpretations.get((entry["router"], c), [])
                                        for c in [x["command"] for x in entry["commands"]] + unevaluated.get(entry["router"], [])}
            # Each router's unevaluated commands go in the first section it appears in.
            if entry["router"] in unevaluated and entry["router"] not in shown:
                shown.add(entry["router"])
                entry["unevaluated"] = unevaluated[entry["router"]]
                entry["unevaluated_n"] = unevaluated_numbers(entries.get(entry["router"]), unevaluated[entry["router"]])
        routing = []
        for name in spec.get("routing", []):
            if node_ids.get(name) not in data["routing"]:
                continue
            rows = [r for r in route_entries.get(name, {}).get("rows", [])
                    if letters is None or consigna_letter(r["consigna"]) in letters]
            router_routing = data["routing"][node_ids[name]]
            if rows:
                # Only the routes the consignas are about, not the whole table.
                found_ids = {r["found_id"] for r in rows}
                router_routing = router_routing | {
                    "routes": [r for r in router_routing["routes"] if r["id"] in found_ids]}
            routing.append({"router": name, "routing": router_routing, "rows": rows})
        misplaced = [item | {"router": entry["router"]}
                     for entry in entries.values() for item in entry["misplaced"]
                     if letters is not None and consigna_letter(item["consigna"]) in letters]

        has_warnings = (
            any(row["problems"] for entry in firewall for row in entry["rows"])
            or bool(misplaced)
            or any(entry["unevaluated"] for entry in firewall)
            or any(entry["policy_errors"] for entry in firewall)
            or any(part["routing"]["warnings"]["routing"] or any(row["problems"] for row in part["rows"])
                   for part in routing)
        )
        sections.append({
            "title": spec["title"],
            "firewall": firewall,
            "misplaced": misplaced,
            "routing": routing,
            "has_warnings": has_warnings,
        })

    # Only the routers that are not shown in any section stay here.
    others = [{"router": name, "commands": commands,
               "interpretations": {c: interpretations.get((name, c), []) for c in commands}}
              for name, commands in unevaluated.items() if name not in shown]

    data["firewall_sections"] = {"sections": sections, "others": sorted(others, key=lambda o: o["router"])}

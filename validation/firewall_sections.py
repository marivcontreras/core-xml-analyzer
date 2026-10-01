from utils.firewall_config import get_firewall_sections
from validation.firewall_validation import is_masquerade


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
    }


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

    sections = []
    for spec in specs:
        letters = {str(c).upper() for c in spec["consignas"]} if spec.get("consignas") else None
        firewall = [section_entry(entries[name], letters) for name in spec.get("firewall", []) if name in entries]
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

    # Commands that no consigna claimed (MASQUERADE has its own section).
    claimed = {(entry["router"], c["command"])
               for entry in entries.values() for c in entry["commands"] if c["consigna"]}
    others = []
    for node_id, device in data["devices"].items():
        commands = [r["command"] for r in data["routing"].get(node_id, {}).get("iptables", [])
                    if not is_masquerade(r) and (device["name"], r["command"]) not in claimed]
        if commands:
            others.append({"router": device["name"], "commands": commands})

    data["firewall_sections"] = {"sections": sections, "others": sorted(others, key=lambda o: o["router"])}

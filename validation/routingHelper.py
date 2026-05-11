ANY = "__ANY__"
AUTO = "__AUTO__"

def clone_with_prefix_type(route, prefix_type):
    cloned = dict(route)
    cloned["prefix_type"] = prefix_type
    return cloned

def direct(iface=None):
    return {
        "type": "direct",
        "via": None,
        "via_info": None,
        "dev": iface,
        "table": "local",
        "dst": AUTO,
        "score": 999,
        "is_default": False,
        "is_policy": False
    }


def default(iface, via):
    normalized_vias = []

    node, interface = via.rsplit("-", 1)

    normalized_vias.append({
            "node": node,
            "interface": interface,
            "type": "neighbor"
        })

    base_route =  {
        "type": "indirect",
        "via": AUTO,
        "via_info": normalized_vias,
        "dev": iface,
        "table": "main",
        "dst": "default",
        "score": 0,
        "is_default": True,
        "is_policy": False
    }

    return [
        clone_with_prefix_type(base_route, "global"),
        clone_with_prefix_type(base_route, "site")
    ]

def defaultSite(iface, via):
    normalized_vias = []

    node, interface = via.rsplit("-", 1)

    normalized_vias.append({
            "node": node,
            "interface": interface,
            "type": "neighbor"
        })

    base_route =  {
        "type": "indirect",
        "via": AUTO,
        "via_info": normalized_vias,
        "dev": iface,
        "table": "main",
        "dst": "default",
        "score": 0,
        "is_default": True,
        "is_policy": False
    }

    return [
        clone_with_prefix_type(base_route, "site")
    ]


def indirect(vias, devs=None):
    normalized_vias = []

    for via in vias:
        node, interface = via.rsplit("-", 1)

        normalized_vias.append({
            "node": node,
            "interface": interface,
            "type": "neighbor"
        })

    base_route = {
        "type": "indirect",
        "via": AUTO,
        "via_info": normalized_vias,
        "dev": devs if devs else ANY,
        "table": "main",
        "dst": AUTO,
        "score": ANY,
        "is_default": ANY,
        "is_policy": False
    }

    return [
        clone_with_prefix_type(base_route, "global"),
        clone_with_prefix_type(base_route, "site")
    ]

def indirectSite(vias, devs=None):
    normalized_vias = []

    for via in vias:
        node, interface = via.rsplit("-", 1)

        normalized_vias.append({
            "node": node,
            "interface": interface,
            "type": "neighbor"
        })

    base_route = {
        "type": "indirect",
        "via": AUTO,
        "via_info": normalized_vias,
        "dev": devs if devs else ANY,
        "table": "main",
        "dst": AUTO,
        "score": ANY,
        "is_default": ANY,
        "is_policy": False
    }

    return [
        clone_with_prefix_type(base_route, "site")
    ]


EXPECTED_ROUTING_MATRIX = {
    "R1-DC": {
        "SwDataCenter": direct("eth0"),
        "WVentas": default("eth1", "R4-eth1"),
        "SwVentas": default("eth1", "R4-eth1"),
        "WGuest": default("eth1", "R4-eth1"),
        "SwAdmin": defaultSite("eth1", "R4-eth1"),
        "SwOfiAdmin": defaultSite("eth1", "R4-eth1"),
        "R4<>R1-DC": direct("eth1"),
        "R4<>R5": default("eth1", "R4-eth1"),
        "R5<>R6": default("eth1", "R4-eth1"),
        "R5<>R3": default("eth1", "R4-eth1"),
        "R4<>R3": default("eth1", "R4-eth1"),
        "R2<>R3": default("eth1", "R4-eth1"),
        "R2<>R4": default("eth1", "R4-eth1")
    },

    "R6": {
        "SwDataCenter": default("eth2", "R5-eth0"),
        "WVentas": direct("eth0"),
        "SwVentas": direct("eth1"),
        "WGuest": default("eth2", "R5-eth0"),
        "SwAdmin": defaultSite("eth2", "R5-eth0"),
        "SwOfiAdmin": defaultSite("eth2", "R5-eth0"),
        "R4<>R1-DC": default("eth2", "R5-eth0"),
        "R4<>R5": default("eth2", "R5-eth0"),
        "R5<>R6": direct("eth2"),
        "R5<>R3": default("eth2", "R5-eth0"),
        "R4<>R3": default("eth2", "R5-eth0"),
        "R2<>R3": default("eth2", "R5-eth0"),
        "R2<>R4": default("eth2", "R5-eth0")
    },

    "R3": {
        "SwDataCenter": indirect(
            ["R2-eth1", "R4-eth3", "R5-eth3"]
        ),

        "WVentas": indirect(
            ["R2-eth1", "R4-eth3", "R5-eth3"]
        ),

        "SwVentas": indirect(
            ["R2-eth1", "R4-eth3", "R5-eth3"]
        ),

        "WGuest": indirect(
            ["R2-eth1", "R4-eth3", "R5-eth3"]
        ),

        "SwAdmin": direct("eth0"),
        "SwOfiAdmin": direct("eth1"),

        "R4<>R1-DC": indirect(
            ["R2-eth1", "R4-eth3", "R5-eth3"]
        ),

        "R4<>R5": indirect(
            ["R2-eth1", "R4-eth3", "R5-eth3"]
        ),

        "R5<>R6": indirect(
            ["R2-eth1", "R4-eth3", "R5-eth3"]
        ),

        "R5<>R3": direct("eth2"),
        "R4<>R3": direct("eth4"),
        "R2<>R3": direct("eth3"),

        "R2<>R4": indirect(
            ["R2-eth1", "R4-eth3", "R5-eth3"]
        )
    },

    "R5": {
        "SwDataCenter": indirect(
            ["R4-eth0", "R3-eth2"]
        ),

        "WVentas": indirect(
            ["R6-eth2"]
        ),

        "SwVentas": indirect(
            ["R6-eth2"]
        ),

        "WGuest": direct("eth1"),

        "SwAdmin": indirectSite(
            ["R4-eth0", "R3-eth2"]
        ),

        "SwOfiAdmin": indirectSite(
            ["R4-eth0", "R3-eth2"]
        ),

        "R1-DC<>R4": indirect(
            ["R4-eth0", "R3-eth2"]
        ),

        "R4<>R5": direct("eth2"),
        "R5<>R6": direct("eth0"),
        "R5<>R3": direct("eth3"),

        "R4<>R3": indirect(
            ["R4-eth0", "R3-eth2"]
        ),

        "R2<>R3": indirect(
            ["R4-eth0", "R3-eth2"]
        ),

        "R2<>R4": indirect(
            ["R4-eth0", "R3-eth2"]
        )
    },

    "R4": {
        "SwDataCenter": indirect(
            ["R1-DC-eth1"]
        ),

        "WVentas": indirect(
            ["R5-eth2", "R3-eth4"]
        ),

        "SwVentas": indirect(
            ["R5-eth2", "R3-eth4"]
        ),

        "WGuest": indirect(
            ["R5-eth2", "R3-eth4"]
        ),

        "SwAdmin": indirectSite(
            ["R5-eth2", "R3-eth4"]
        ),

        "SwOfiAdmin": indirectSite(
            ["R5-eth2", "R3-eth4"]
        ),

        "R1-DC<>R4": direct("eth1"),
        "R4<>R5": direct("eth0"),

        "R5<>R6": indirect(
            ["R5-eth2", "R3-eth4"]
        ),

        "R5<>R3": indirect(
            ["R5-eth2", "R3-eth4"]
        ),

        "R4<>R3": direct("eth3"),

        "R2<>R3": indirect(
            ["R5-eth2", "R3-eth4"]
        ),

        "R2<>R4": direct("eth2")
    },

    "R2": {
        "SwDataCenter": indirect(
            ["R4-eth2", "R3-eth3"]
        ),

        "WVentas": indirect(
            ["R4-eth2", "R3-eth3"]
        ),

        "SwVentas": indirect(
            ["R4-eth2", "R3-eth3"]
        ),

        "WGuest": indirect(
            ["R4-eth2", "R3-eth3"]
        ),

        "SwAdmin": indirectSite(
            ["R4-eth2", "R3-eth3"]
        ),

        "SwOfiAdmin": indirectSite(
            ["R4-eth2", "R3-eth3"]
        ),

        "R1-DC<>R4": indirect(
            ["R4-eth2", "R3-eth3"]
        ),

        "R4<>R5": indirect(
            ["R4-eth2", "R3-eth3"]
        ),

        "R5<>R6": indirect(
            ["R4-eth2", "R3-eth3"]
        ),

        "R5<>R3": indirect(
            ["R4-eth2", "R3-eth3"]
        ),

        "R4<>R3": indirect(
            ["R4-eth2", "R3-eth3"]
        ),

        "R2<>R3": direct("eth1"),
        "R2<>R4": direct("eth0")
    }
}
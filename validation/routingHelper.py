ANY = "__ANY__"
AUTO = "__AUTO__"


def direct(iface=None):
    return {
        "type": "direct",
        "via": None,
        "via_info": None,
        "dev": iface,
        "table": "local",
        "dst": None,
        "score": 999,
        "is_default": False,
        "is_policy": False
    }


def default():
    return {
        "type": "default",
        "via": AUTO,
        "via_info": ANY,
        "dev": ANY,
        "table": "main",
        "dst": "default",
        "score": 0,
        "is_default": True,
        "is_policy": False
    }


def indirect(vias, devs=None):
    normalized_vias = []

    for via in vias:
        node, interface = via.split("-")

        normalized_vias.append({
            "node": node,
            "interface": interface,
            "type": "neighbor"
        })

    return {
        "type": "indirect",
        "via": AUTO,
        "via_info": normalized_vias,
        "dev": devs if devs else ANY,
        "table": "main",
        "dst": AUTO,
        "score": ANY,
        "is_default": False,
        "is_policy": False
    }


EXPECTED_ROUTING_MATRIX = {
    "R1-DC": {
        "SwDataCenter": direct("eth0"),
        "WVentas": default(),
        "SwVentas": default(),
        "WGuest": default(),
        "SwAdmin": default(),
        "SwOfiAdmin": default(),
        "R4<>R1-DC": direct("eth1"),
        "R4<>R5": default(),
        "R5<>R6": default(),
        "R5<>R3": default(),
        "R4<>R3": default(),
        "R2<>R3": default(),
        "R2<>R4": default()
    },

    "R6": {
        "SwDataCenter": default(),
        "WVentas": direct("eth0"),
        "SwVentas": direct("eth1"),
        "WGuest": default(),
        "SwAdmin": default(),
        "SwOfiAdmin": default(),
        "R4<>R1-DC": default(),
        "R4<>R5": default(),
        "R5<>R6": direct("eth2"),
        "R5<>R3": default(),
        "R4<>R3": default(),
        "R2<>R3": default(),
        "R2<>R4": default()
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

        "SwAdmin": indirect(
            ["R4-eth0", "R3-eth2"]
        ),

        "SwOfiAdmin": indirect(
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
            ["R1-eth1"]
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

        "SwAdmin": indirect(
            ["R5-eth2", "R3-eth4"]
        ),

        "SwOfiAdmin": indirect(
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

        "SwAdmin": indirect(
            ["R4-eth2", "R3-eth3"]
        ),

        "SwOfiAdmin": indirect(
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
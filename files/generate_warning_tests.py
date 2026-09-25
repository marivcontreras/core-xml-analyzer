"""Generate rdc1 + rdc2 warning test XMLs from the base solutions.

rdc2 base: files/rdc2/bien.xml    -> files/rdc2/tests/
rdc1 base: files/rdc1/resolucionTPE.xml -> files/rdc1/tests/

Each test applies surgical text replacements that inject specific error(s).
"""
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(rel):
    with open(os.path.join(REPO, rel), encoding="utf-8") as f:
        return f.read()

BASE2 = load("files/rdc2/bien.xml")
BASE1 = load("files/rdc1/resolucionTPE.xml")


def repl(text, old, new, required=True):
    if old not in text and required:
        raise SystemExit(f"PATTERN NOT FOUND:\n{old!r}")
    return text.replace(old, new, 1)


def write(subdir, name, text, notes):
    os.makedirs(subdir, exist_ok=True)
    path = os.path.join(subdir, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"wrote {path}")
    for n in notes:
        print("   -", n)


OUT2 = os.path.join(REPO, "files/rdc2/tests")
OUT1 = os.path.join(REPO, "files/rdc1/tests")

# ===========================================================================
# rdc2
# ===========================================================================

def gen_networks_prefijos():
    t = BASE2
    t = repl(t, "ip -6 addr add 2001:0:0:2::1/64 dev eth0",
                "ip -6 addr add 2001:0:0:2::1/48 dev eth0")           # invalid_prefix_length
    t = repl(t, "ip -6 addr add 2001:0:0:3::1/64 dev eth1",
                "ip -6 addr add 2001:0:0:3::1/64 dev eth1\n"
                "ip -6 addr add 2001:0:0:33::1/64 dev eth1\n"          # too_many_prefixes
                "ip -6 addr add 3000:0:0:3::1/64 dev eth1\n"           # invalid_prefixes (unknown block)
                "ip -6 addr add 2001:zz::1/64 dev eth1")               # invalid_prefixes (bad syntax)
    t = repl(t, "ip -6 addr add 2001:0:0:1::1/64 dev eth1",
                "ip -6 addr add 2001:0:0:2::99/64 dev eth1")           # duplicated_prefix
    write(OUT2, "test_networks_prefijos.xml", t, [
        "invalid_prefix_length: R6 eth0 global /48",
        "too_many_prefixes: R6 eth1 con 4 bloques",
        "invalid_prefixes: 3000::/64 (bloque no usado) y 2001:zz (sintaxis)",
        "duplicated_prefix: R5 eth1 reusa 2001:0:0:2::/64",
    ])


def gen_networks_faltantes():
    t = BASE2
    # missing_site_prefix on WVentas (R6 eth0): drop fd00 from BOTH StaticRoute
    # and radvd, so no source re-adds it.
    t = repl(t, "ip -6 addr add FD00:0:0:2::1/64 dev eth0\n", "")
    t = repl(t,
        "    prefix FD00:0:0:2::/64 {\n"
        "        AdvOnLink on;\n"
        "        AdvAutonomous on;\n"
        "    };\n", "")
    # missing_global_prefix on SwVentas (R6 eth1): drop 2001 from StaticRoute + radvd
    t = repl(t, "ip -6 addr add 2001:0:0:3::1/64 dev eth1\n", "")
    t = repl(t,
        "    prefix 2001:0:0:3::/64 {\n"
        "        AdvOnLink on;\n"
        "        AdvAutonomous on;\n"
        "    };\n", "")
    # admin_with_global: R3 eth0 (SwAdmin, site only) gets a global
    t = repl(t, "ip -6 addr add FD00:0:0:4::1/64 dev eth0",
                "ip -6 addr add FD00:0:0:4::1/64 dev eth0\n"
                "ip -6 addr add 2001:0:0:4::1/64 dev eth0")
    # ipv4_with_other_prefixes: add IPv4 on R1-DC eth0 (already IPv6)
    t = repl(t, "ip -6 addr add 2001:0:0:0::1/64 dev eth0",
                "ip -6 addr add 2001:0:0:0::1/64 dev eth0\n"
                "ip addr add 10.14.0.5/24 dev eth0")
    write(OUT2, "test_networks_faltantes.xml", t, [
        "missing_site_prefix: WVentas (R6 eth0) sin fd00 (StaticRoute + radvd)",
        "missing_global_prefix: SwVentas (R6 eth1) sin 2001 (StaticRoute + radvd)",
        "admin_with_global: SwAdmin (R3 eth0) con global",
        "ipv4_with_other_prefixes: R1-DC eth0 IPv4+IPv6",
    ])


def gen_p2p():
    t = BASE2
    t = repl(t, "ip -6 addr add 2001:0:0:FF::A/127 dev eth1\n", "")   # missing_global+site+ip_p2p
    t = repl(t, "ip -6 addr add FD00:0:0:FF::A/127 dev eth1\n", "")
    t = repl(t, "ip -6 addr add 2001:0:0:FF::3/127 dev eth2",
                "ip -6 addr add 2001:0:0:EE::3/127 dev eth2")          # global_mismatch
    t = repl(t, "ip -6 addr add FD00:0:0:FF::3/127 dev eth2",
                "ip -6 addr add FD00:0:0:EE::3/127 dev eth2")          # site_mismatch
    write(OUT2, "test_p2p.xml", t, [
        "p2p_missing_global + p2p_missing_site + missing_ip_p2p: R4 eth1 sin direcciones",
        "p2p_global_mismatch + p2p_site_mismatch: R4 eth2 bloque EE vs R3 FF",
    ])


def gen_sintaxis():
    t = BASE2
    anchor = "ip -6 addr add 2001:0:0:2::1/64 dev eth0"
    t = repl(t, anchor,
        anchor + "\n"
        "ip -6 addr add 2001:0:0:2::1/64\n"              # invalid_ip_command (no dev)
        "ip -6 addr add FD00:0:0:FF:8/127 dev eth0\n"    # invalid_ipv6
        "ip -6 addr add 2001:0:0:9::1/200 dev eth0\n"    # invalid_prefix_length_ipv6
        "ip -6 addr add 2001:0:0:22::/64 dev eth0\n"     # net_ip_assigned (network base host::0)
        "ip -6 addr add 2001:0:0:8::1/64 dev eth9")      # interface_not_found
    for line in [
        "ip -6 addr add 2001:0:0:FF::2/127 dev eth0\n",
        "ip -6 addr add FD00:0:0:FF::2/127 dev eth0\n",
        "ip -6 addr add 2001:0:0:FF::4/127 dev eth1\n",
        "ip -6 addr add FD00:0:0:FF::4/127 dev eth1\n",
    ]:
        t = repl(t, line, "")                            # missing_ip_command (R2)
    write(OUT2, "test_sintaxis.xml", t, [
        "invalid_ip_command, invalid_ipv6, invalid_prefix_length_ipv6, net_ip_assigned, interface_not_found (R6 eth0)",
        "missing_ip_command: R2 sin comandos ip addr",
    ])


def gen_radvd():
    t = BASE2
    t = repl(t, "ip -6 addr add 2001:0:0:3::1/64 dev eth1\n", "")     # radvd_without_ip (R6 eth1)
    t = repl(t, "ip -6 addr add FD00:0:0:3::1/64 dev eth1\n", "")
    t = repl(t, "ip -6 addr add 2001:0:0:2::1/64 dev eth0",
                "ip -6 addr add 2001:0:0:88::1/64 dev eth0")          # ip_outside_radvd_prefix
    write(OUT2, "test_radvd.xml", t, [
        "radvd_without_ip: R6 eth1 anuncia radvd sin direcciones",
        "ip_outside_radvd_prefix: R6 eth0 con 2001:0:0:88 fuera del anunciado",
    ])


def gen_routing():
    t = BASE2
    # missing_route: R5 has a route to 2001:0:0:2::/63; remove one expected R5 route
    # to trigger missing_route (a route the matrix expects but is absent), while
    # keeping the network reachable enough to avoid pure unreachable.
    t = repl(t, "ip -6 route add FD00:0:0:4::/63 via FD00:0:0:ff::c dev eth3\n", "")  # missing_route
    # invalid_route_field: break a via on an existing R5 route
    t = repl(t, "ip -6 route add 2001:0:0:2::/63 via 2001:0:0:ff::f dev eth0",
                "ip -6 route add 2001:0:0:2::/63 via 2001:0:0:ff::EE dev eth0")       # invalid_route_field
    write(OUT2, "test_routing.xml", t, [
        "missing_route: R5 sin ruta hacia FD00:0:0:4::/63",
        "invalid_route_field: R5 ruta a 2001:0:0:2::/63 con via incorrecto",
    ])


def gen_isp():
    t = BASE2
    t = repl(t, "\nip route add 100.64.1.0/24 via 162.120.0.2 dev eth1", "")  # no_indirect/missing_isp
    t = repl(t, "ip route add 100.64.0.0/24 via 162.120.0.1 dev eth0",
                "ip route add 100.64.0.0/24 via 162.120.0.1 dev eth0\n"
                "ip route add default via 162.120.0.1 dev eth0")               # invalid_default_route
    write(OUT2, "test_isp.xml", t, [
        "no_indirect_routes / missing_isp_route: ISP-Intranet sin ruta a 100.64.1.0/24",
        "invalid_default_route: ISP-Casa con default",
    ])


def gen_tunnels():
    t = BASE2
    t = repl(t, "ip tunnel add tnl mode sit local 100.64.0.2 remote 100.64.1.2 dev eth2\n", "")  # no_tunnel (R2)
    t = repl(t, "ip tunnel add tnl mode sit local 100.64.1.2 remote 100.64.0.2 dev eth0",
                "ip tunnel add tnl mode sit local 100.64.9.9 remote 100.64.0.2 dev eth0")         # invalid_tunnel
    write(OUT2, "test_tunnels.xml", t, [
        "no_tunnel_configured: R2 sin tunel",
        "invalid_tunnel + tunnel_invalid_local: R-Casa con local invalido",
    ])


def gen_devices_faltantes():
    t = BASE2
    t = repl(t,
        '    <device id="6" name="R6" icon="" canvas="1" type="router" class="" image="" compose="" compose_name="">\n'
        '      <position x="534.2706298828125" y="529.537109375" lat="47.574352879000934" lon="-122.12512506665979" alt="2.0"/>\n'
        '      <services>\n'
        '        <service name="radvd"/>\n'
        '        <service name="StaticRoute"/>\n'
        '        <service name="IPForward"/>\n'
        '      </services>\n'
        '    </device>\n', "")
    t = repl(t,
        '    <network id="12" name="SwOfiAdmin" icon="" canvas="1" type="SWITCH">\n'
        '      <position x="828.4851684570312" y="318.9634094238281" lat="47.57626706324473" lon="-122.12116060540761" alt="2.0"/>\n'
        '    </network>\n', "")
    write(OUT2, "test_devices_faltantes.xml", t, [
        "missing_configured_router: R6 ausente del XML",
        "missing_configured_network: SwOfiAdmin ausente",
    ])


# ===========================================================================
# rdc1 (IPv4 only)
# ===========================================================================

def gen_rdc1_networks():
    t = BASE1
    # invalid_prefix_length: R3 eth0 is SwAdmin (expected /28); change to /24
    t = repl(t, "ip addr add 10.14.1.162/28 dev eth0",
                "ip addr add 10.14.1.162/24 dev eth0")
    # too_many_prefixes (rdc1 max=1): add a 2nd block on R5 eth1 (SwComp)
    t = repl(t, "ip addr add 10.14.1.113/29 dev eth1",
                "ip addr add 10.14.1.113/29 dev eth1\n"
                "ip addr add 10.14.1.200/29 dev eth1")
    # duplicated_prefix: give R6 eth1 a prefix already used elsewhere (Sw-Troncal 10.14.1.128/27)
    t = repl(t, "ip addr add 10.14.1.1/26 dev eth1",
                "ip addr add 10.14.1.128/27 dev eth1")
    write(OUT1, "test_networks.xml", t, [
        "invalid_prefix_length: R3 eth0 /24 (esperado /28)",
        "too_many_prefixes: R5 eth1 con 2 bloques (rdc1 max=1)",
        "duplicated_prefix: R6 eth1 reusa 10.14.1.128/27",
    ])


def gen_rdc1_p2p():
    t = BASE1
    # p2p R5<>R6: R5 eth3 = 10.14.1.121/30, R6 eth0 = 10.14.1.122/30 (same block)
    # p2p_ipv4_mismatch: change R5 eth3 to a different block
    t = repl(t, "ip addr add 10.14.1.121/30 dev eth3",
                "ip addr add 10.14.2.121/30 dev eth3")
    # p2p_missing_ipv4: remove R6 eth0 address (the other p2p endpoint)
    t = repl(t, "ip addr add 10.14.1.122/30 dev eth0\n", "")
    write(OUT1, "test_p2p.xml", t, [
        "p2p_ipv4_mismatch: R5 eth3 en bloque 10.14.2 vs R6 eth0 en 10.14.1",
        "p2p_missing_ipv4: R6 eth0 sin direccion IPv4",
    ])


def gen_rdc1_sintaxis():
    t = BASE1
    anchor = "ip addr add 201.0.2.1/24 dev eth0"
    t = repl(t, anchor,
        anchor + "\n"
        "ip addr add 201.0.2.1/24\n"               # invalid_ip_command (no dev)
        "ip addr add 300.0.0.1/24 dev eth0\n"      # invalid_ipv4 (octet > 255)
        "ip addr add 10.14.0.0/24 dev eth0\n"      # net_ip_assigned (network base)
        "ip addr add 201.0.2.9/24 dev eth9")       # interface_not_found
    write(OUT1, "test_sintaxis.xml", t, [
        "invalid_ip_command: sin dev (R1 eth0)",
        "invalid_ipv4: 300.0.0.1 octeto invalido",
        "net_ip_assigned: 10.14.0.0 direccion base",
        "interface_not_found: dev eth9",
    ])


def gen_rdc1_routing():
    t = BASE1
    # missing_route / invalid_route_field: break R4 routes
    t = repl(t, "ip route add 10.14.0.0/24 via 10.14.1.162 dev eth1",
                "ip route add 10.14.0.0/24 via 10.14.9.99 dev eth1")   # invalid via
    t = repl(t, "ip route add 10.14.1.128/27 via 10.14.1.162 dev eth1\n", "")  # missing route
    write(OUT1, "test_routing.xml", t, [
        "invalid_route_field: R4 ruta a 10.14.0.0/24 con via incorrecto",
        "missing_route: R4 sin ruta a 10.14.1.128/27",
    ])


if __name__ == "__main__":
    gen_networks_prefijos()
    gen_networks_faltantes()
    gen_p2p()
    gen_sintaxis()
    gen_radvd()
    gen_routing()
    gen_isp()
    gen_tunnels()
    gen_devices_faltantes()
    gen_rdc1_networks()
    gen_rdc1_p2p()
    gen_rdc1_sintaxis()
    gen_rdc1_routing()

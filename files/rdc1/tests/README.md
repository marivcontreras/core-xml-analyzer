# Tests de warnings — rdc1

XMLs derivados de `files/rdc1/resolucionTPE.xml` (solución correcta) con errores
inyectados. Regenerables con `python _gen_tests.py` desde la raíz del repo.

Config a usar: `rdc1`. Solo IPv4, routing e iptables.

| Archivo | Warnings esperados | Estado observado |
| --- | --- | --- |
| `test_networks.xml` | `invalid_prefix_length`, `too_many_prefixes` (max=1), `duplicated_prefix` | OK; aparecen además `invalid_last_octet`/`net_ip_assigned` colaterales |
| `test_p2p.xml` | `p2p_ipv4_mismatch`, `p2p_missing_ipv4` | NO disparan pese a datos correctos (BUG #4) |
| `test_sintaxis.xml` | `invalid_ip_command`, `invalid_ipv4`, `net_ip_assigned`, `interface_not_found` | OK salvo `net_ip_assigned` (BUG #3) |
| `test_routing.xml` | `missing_route`, `invalid_route_field*` | Sale `unreachable_network` (revisar) |

Nota: los warnings IPv6 (site/global, radvd, tunnels, policy) no aplican a rdc1
y deben quedar suprimidos por el gate de subject/ipv6_support.

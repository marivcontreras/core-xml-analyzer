# Tests de warnings — rdc2

XMLs derivados de `files/rdc2/bien.xml` (solución correcta) con errores inyectados
para verificar que el analizador emite los warnings esperados. Regenerables con
`python _gen_tests.py` desde la raíz del repo.

Config a usar: `rdc2`.

| Archivo | Warnings esperados | Estado observado |
| --- | --- | --- |
| `test_networks_prefijos.xml` | `invalid_prefix_length`, `too_many_prefixes`, `invalid_prefixes` (bloque + sintaxis), `duplicated_prefix` | OK salvo `invalid_prefixes` (BUG #1) |
| `test_networks_faltantes.xml` | `missing_site_prefix`, `missing_global_prefix`, `admin_with_global`, `ipv4_with_other_prefixes` | OK |
| `test_p2p.xml` | `p2p_missing_global`, `p2p_missing_site`, `missing_ip_p2p`, `p2p_global_mismatch`, `p2p_site_mismatch` | OK |
| `test_sintaxis.xml` | `invalid_ip_command`, `invalid_ipv6`, `invalid_prefix_length_ipv6`, `net_ip_assigned`, `interface_not_found`, `missing_ip_command` | OK salvo `net_ip_assigned` (BUG #3) |
| `test_radvd.xml` | `radvd_without_ip`, `ip_outside_radvd_prefix` | OK |
| `test_routing.xml` | `missing_route`, `invalid_route_field*` | Sale `unreachable_network` en vez de `missing_route` (revisar) |
| `test_isp.xml` | `no_indirect_routes`, `missing_isp_route`, `invalid_default_route` | `invalid_default_route` a confirmar |
| `test_tunnels.xml` | `no_tunnel_configured`, `invalid_tunnel`, `tunnel_invalid_local` | OK |
| `test_devices_faltantes.xml` | `missing_configured_router`, `missing_configured_network` | OK |

Nota: `missing_ip_command: 3` aparece en TODOS (y en `bien.xml` base) — es un falso
positivo preexistente (BUG #2). Romper direcciones/rutas produce warnings en cascada
(`unreachable_network`, `invalid_route_field_*`) además del objetivo; es esperado.

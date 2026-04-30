# 🧠 CORE XML Network Analyzer

![Python](https://img.shields.io/badge/python-3.10+-blue)
![Status](https://img.shields.io/badge/status-active-success)
![License](https://img.shields.io/badge/license-MIT-green)

Analizador de topologías XML generadas por **CORE Network Emulator** que construye un modelo lógico de redes y detecta errores comunes en configuraciones IPv6.

---

## 🚀 Features

### 🔍 XML Parsing

* Parseo completo de topologías exportadas desde CORE
* Extracción de:

  * Dispositivos (`devices`)
  * Redes (`networks`)
  * Enlaces (`links`)
  * Servicios (`StaticRoute`, `radvd`)
* Unificación de nodos (`devices + networks → nodes`)

---

### 🌐 Modelado de Redes

* Construcción de redes reales (no solo links):

  * LAN (switches)
  * Wireless
  * Enlaces punto a punto (router ↔ router)
* Detección automática de:

  * Miembros por red
  * Interfaces involucradas
* Separación entre:

  * Redes L2 (broadcast domains)
  * Enlaces P2P

---

### 🧠 Inferencia Inteligente de Prefijos

Prioridad de fuentes:

1. `StaticRoute` (`ip addr`)
2. `radvd` (prefijos anunciados)
3. Fallback: interfaces del XML

✔ Filtrado por interfaz
✔ Soporte IPv4 / IPv6
✔ Clasificación:

* IPv6 Global (`2001::/16`)
* IPv6 Site (`fd00::/8`)
* IPv4
* Unknown

---

### 📡 Análisis de Servicios

* Parsing de:

  * `ip -6 addr add`
  * Configuración de `radvd`
* Asociación precisa:

  * Nodo → interfaz → prefijo

---

### 🔗 Validación de Redes

* LAN/WiFi → `/64`
* P2P → `/127`
* Consistencia entre extremos
* Validación de bloques de direcciones

---

### 📊 Reporte

* Resumen general:

  * Dispositivos
  * Routers
  * Links
  * Redes
* Tabla de redes:

  * Nombre
  * Tipo
  * Miembros
  * Prefijos

---

## ⚠️ Warnings Detectados

### 🧩 Configuración faltante

* Router sin IP en interfaz
* Interfaces P2P sin dirección

---

### 🌍 Problemas de Prefijos

* Prefijo desconocido
* Demasiados bloques en una red
* Mezcla incorrecta de direcciones

---

### 📏 Máscaras incorrectas

* LAN/Wireless sin `/64`
* P2P sin `/127`

---

### 🧱 Prefijos faltantes

* Falta prefijo site (`fd00::/8`)
* Falta prefijo global (`2001::/16`)

---

### 🔒 Reglas especiales

* Redes admin no deben usar direcciones globales

---

### 🔗 Inconsistencias P2P

* Distintos bloques entre extremos
* Falta dirección en un endpoint

---

### 📡 Problemas con RADVD

* RADVD sin direcciones asignadas
* Direcciones fuera del prefijo anunciado

---

## ⚙️ Instalación

```bash
git clone https://github.com/your-repo/core-xml-analyzer.git
cd core-xml-analyzer
pip install -r requirements.txt
```

---

## ▶️ Uso

```python
from parser import parse_xml, summarize, pretty_networks

with open("topology.xml") as f:
    xml = f.read()

data = parse_xml(xml)

print(summarize(data))
print(pretty_networks(data))
```

---

## 📄 Ejemplo de Output

### 🔹 Summary

```json
{
  "devices_total": 5,
  "routers": 2,
  "links": 4,
  "networks": 3,
  "warnings": [
    "LAN1: prefijo global faltante (fd00::/64)",
    "R1 <-> R2: R1 (eth1) sin dirección global"
  ]
}
```

---

### 🔹 Networks

```json
[
  {
    "name": "LAN1",
    "kind": "lan",
    "members": ["R1", "PC1"],
    "prefixes": ["fd00::/64"]
  },
  {
    "name": "R1 <-> R2",
    "kind": "point-to-point",
    "members": ["R1", "R2"],
    "prefixes": ["2001:0:0:ff::/127", "fd00:0:0:ff::/127"]
  }
]
```

---

## 🧠 Decisiones de Diseño

* ❌ No se listan todos los prefijos detectados
* ✅ Solo se consideran los relevantes a cada red
* ✅ Se prioriza configuración en `services` sobre XML
* ✅ Asociación estricta por interfaz

---

## 📌 Futuras mejoras

* Export a HTML report
* Visualización gráfica de topología
* Soporte completo IPv4 validation
* CLI interface


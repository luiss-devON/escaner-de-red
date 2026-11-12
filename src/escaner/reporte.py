"""Salidas: tabla en terminal, JSON, CSV y reporte HTML."""

from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime

from .descubrimiento import Dispositivo
from .historial import Cambios

COLUMNAS = ("ip", "mac", "nombre_host", "alias", "metodo", "mac_aleatoria", "este_equipo")


def nombre_visible(d: Dispositivo) -> str:
    nombre = d.alias or d.nombre_host or "-"
    return f"{nombre} (este equipo)" if d.este_equipo else nombre


def tabla(dispositivos: list[Dispositivo]) -> str:
    filas = [("IP", "MAC", "NOMBRE", "DETECCIÓN")]
    for d in dispositivos:
        mac = (d.mac or "-") + (" *" if d.mac_aleatoria else "")
        filas.append((d.ip, mac, nombre_visible(d), d.metodo))
    anchos = [max(len(f[i]) for f in filas) for i in range(4)]
    lineas = ["  ".join(c.ljust(a) for c, a in zip(f, anchos)).rstrip() for f in filas]
    lineas.insert(1, "─" * len(lineas[0]))
    if any(d.mac_aleatoria for d in dispositivos):
        lineas.append("\n* MAC privada/aleatoria (normalmente un celular o tablet).")
    return "\n".join(lineas)


def a_json(dispositivos: list[Dispositivo]) -> str:
    return json.dumps([d.a_dict() for d in dispositivos], indent=2, ensure_ascii=False)


def a_csv(dispositivos: list[Dispositivo]) -> str:
    salida = io.StringIO()
    escritor = csv.DictWriter(salida, fieldnames=COLUMNAS, lineterminator="\n")
    escritor.writeheader()
    for d in dispositivos:
        escritor.writerow({k: v for k, v in d.a_dict().items() if k in COLUMNAS})
    return salida.getvalue()


def a_html(dispositivos: list[Dispositivo], red: str, cambios: Cambios | None = None,
           fecha: datetime | None = None) -> str:
    e = html.escape
    fecha_txt = (fecha or datetime.now()).strftime("%Y-%m-%d %H:%M")
    nuevas = {x.get("mac") or f"ip:{x.get('ip')}" for x in (cambios.nuevos if cambios else [])}
    filas = []
    for d in dispositivos:
        es_nuevo = (d.mac or f"ip:{d.ip}") in nuevas
        etiquetas = "".join([
            '<span class="tag nuevo">NUEVO</span>' if es_nuevo else "",
            '<span class="tag">MAC privada</span>' if d.mac_aleatoria else "",
            '<span class="tag tu">tú</span>' if d.este_equipo else "",
        ])
        filas.append(
            f"<tr><td>{e(d.ip)}</td><td><code>{e(d.mac or '-')}</code></td>"
            f"<td>{e(d.alias or d.nombre_host or '-')} {etiquetas}</td><td>{e(d.metodo)}</td></tr>"
        )
    total_nuevos = len(cambios.nuevos) if cambios else 0
    return f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Escaneo de {e(red)}</title>
<style>
body{{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:2rem}}
main{{max-width:900px;margin:auto}} h1{{margin:0 0 .25rem}} .sub{{color:#94a3b8;margin:0 0 1.5rem}}
.cards{{display:flex;gap:1rem;margin-bottom:1.5rem;flex-wrap:wrap}}
.card{{background:#1e293b;border-radius:12px;padding:1rem 1.5rem;min-width:140px}}
.card b{{display:block;font-size:2rem}} .card span{{color:#94a3b8}}
table{{width:100%;border-collapse:collapse;background:#1e293b;border-radius:12px;overflow:hidden}}
th,td{{padding:.7rem 1rem;text-align:left;border-bottom:1px solid #334155}} th{{background:#334155}}
code{{color:#7dd3fc}} .tag{{font-size:.75rem;background:#475569;border-radius:6px;padding:.1rem .4rem;margin-left:.3rem}}
.nuevo{{background:#dc2626}} .tu{{background:#16a34a}}
</style></head><body><main>
<h1>Dispositivos en {e(red)}</h1><p class="sub">Escaneo del {e(fecha_txt)}</p>
<div class="cards"><div class="card"><b>{len(dispositivos)}</b><span>conectados</span></div>
<div class="card"><b>{total_nuevos}</b><span>nuevos</span></div>
<div class="card"><b>{sum(d.mac_aleatoria for d in dispositivos)}</b><span>con MAC privada</span></div></div>
<table><thead><tr><th>IP</th><th>MAC</th><th>Nombre</th><th>Detección</th></tr></thead>
<tbody>{''.join(filas)}</tbody></table>
</main></body></html>
"""

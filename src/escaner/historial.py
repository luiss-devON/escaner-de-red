"""Historial de dispositivos conocidos: detecta equipos nuevos y guarda alias."""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .descubrimiento import Dispositivo
from .red import normalizar_mac


@dataclass
class Cambios:
    primer_escaneo: bool = False
    nuevos: list[dict] = field(default_factory=list)
    desconectados: list[dict] = field(default_factory=list)


def clave(d: Dispositivo) -> str:
    return d.mac or f"ip:{d.ip}"


class Historial:
    def __init__(self, ruta: Path):
        self.ruta = Path(ruta)
        self.aviso: str | None = None
        self.equipos: dict[str, dict] = {}
        if self.ruta.exists():
            try:
                datos = json.loads(self.ruta.read_text(encoding="utf-8"))
                if not isinstance(datos, dict):
                    raise ValueError
                self.equipos = datos
            except ValueError:
                respaldo = self.ruta.with_suffix(".danado.json")
                os.replace(self.ruta, respaldo)
                self.aviso = f"El historial estaba dañado; se guardó una copia en {respaldo} y se empezó de cero."

    def registrar(self, dispositivos: list[Dispositivo], ahora: datetime | None = None) -> Cambios:
        fecha = (ahora or datetime.now()).isoformat(timespec="seconds")
        cambios = Cambios(primer_escaneo=not self.equipos)
        vistos = set()
        for d in dispositivos:
            k = clave(d)
            vistos.add(k)
            previo = self.equipos.get(k)
            if previo is None:
                previo = self.equipos[k] = {"primera_vez": fecha, "alias": None}
                if not cambios.primer_escaneo:
                    cambios.nuevos.append(previo)
            previo.update(ip=d.ip, mac=d.mac, nombre_host=d.nombre_host or previo.get("nombre_host"),
                          ultima_vez=fecha, en_linea=True)
            d.alias = previo.get("alias")
        for k, e in self.equipos.items():
            if k not in vistos and e.get("en_linea"):
                e["en_linea"] = False
                cambios.desconectados.append(e)
        return cambios

    def buscar(self, identificador: str) -> dict | None:
        try:
            return self.equipos.get(normalizar_mac(identificador))
        except ValueError:
            pass
        try:
            ipaddress.IPv4Address(identificador)
        except ValueError:
            return None
        candidatos = [e for e in self.equipos.values() if e.get("ip") == identificador]
        return max(candidatos, key=lambda e: e.get("ultima_vez", ""), default=None)

    def nombrar(self, identificador: str, alias: str) -> bool:
        equipo = self.buscar(identificador)
        if equipo is None:
            return False
        equipo["alias"] = alias.strip() or None
        return True

    def lista(self) -> list[dict]:
        return sorted(self.equipos.values(), key=lambda e: ipaddress.IPv4Address(e.get("ip") or "0.0.0.0"))

    def guardar(self) -> None:
        self.ruta.parent.mkdir(parents=True, exist_ok=True)
        temporal = self.ruta.with_suffix(".tmp")
        temporal.write_text(json.dumps(self.equipos, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(temporal, self.ruta)

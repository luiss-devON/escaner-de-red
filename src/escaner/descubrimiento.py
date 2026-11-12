"""Descubrimiento de dispositivos en la red local (sin permisos de administrador)."""

from __future__ import annotations

import ipaddress
import math
import platform
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Iterable

from .red import es_mac_aleatoria, hosts, ip_local, parsear_tabla_arp

# Puertos usados para detectar equipos que no responden al ping.
PUERTOS_SONDEO = (80, 443, 22, 445, 62078)

_SIN_VENTANA = getattr(subprocess, "CREATE_NO_WINDOW", 0)


@dataclass
class Dispositivo:
    ip: str
    mac: str | None = None
    nombre_host: str | None = None
    alias: str | None = None
    metodo: str = ""
    este_equipo: bool = False

    @property
    def mac_aleatoria(self) -> bool:
        return bool(self.mac) and es_mac_aleatoria(self.mac)

    def a_dict(self) -> dict:
        datos = asdict(self)
        datos["mac_aleatoria"] = self.mac_aleatoria
        return datos


def ping(ip: str, timeout: float = 1.0) -> bool:
    ejecutable = shutil.which("ping")
    if not ejecutable:
        return False
    sistema = platform.system()
    if sistema == "Windows":
        args = [ejecutable, "-n", "1", "-w", str(int(timeout * 1000)), ip]
    elif sistema == "Darwin":
        args = [ejecutable, "-c", "1", "-W", str(int(timeout * 1000)), ip]
    else:
        args = [ejecutable, "-c", "1", "-W", str(max(1, math.ceil(timeout))), ip]
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout + 3, creationflags=_SIN_VENTANA)
    except (subprocess.TimeoutExpired, OSError):
        return False
    # Windows devuelve 0 también con "host inaccesible"; solo una respuesta real trae TTL.
    return r.returncode == 0 and "ttl" in r.stdout.decode(errors="ignore").lower()


def sondeo_tcp(ip: str, puertos: Iterable[int] = PUERTOS_SONDEO, timeout: float = 0.4) -> bool:
    """True si el equipo acepta o rechaza activamente alguna conexión (o sea, existe)."""
    for puerto in puertos:
        try:
            with socket.create_connection((ip, puerto), timeout=timeout):
                return True
        except ConnectionRefusedError:
            return True
        except OSError:
            continue
    return False


def nombre_host(ip: str) -> str | None:
    try:
        nombre = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return None
    return None if nombre == ip else nombre


def leer_tabla_arp() -> dict[str, str]:
    proc = Path("/proc/net/arp")
    try:
        if proc.exists():
            return parsear_tabla_arp(proc.read_text(errors="ignore"))
        if shutil.which("arp"):
            r = subprocess.run(["arp", "-a"], capture_output=True, timeout=10, creationflags=_SIN_VENTANA)
            return parsear_tabla_arp(r.stdout.decode(errors="ignore"))
    except (OSError, subprocess.TimeoutExpired):
        pass
    return {}


def descubrir(
    red: ipaddress.IPv4Network,
    timeout: float = 1.0,
    hilos: int = 100,
    resolver_nombres: bool = True,
    puertos_sondeo: Iterable[int] = PUERTOS_SONDEO,
    progreso: Callable[[int, int], None] | None = None,
) -> list[Dispositivo]:
    ips = hosts(red)
    puertos_sondeo = tuple(puertos_sondeo)
    vivos: dict[str, str] = {}

    def probar(ip: str) -> tuple[str, str | None]:
        if ping(ip, timeout):
            return ip, "ping"
        if sondeo_tcp(ip, puertos_sondeo, min(timeout, 0.4)):
            return ip, "tcp"
        return ip, None

    with ThreadPoolExecutor(max_workers=max(1, min(hilos, len(ips)))) as ex:
        futuros = [ex.submit(probar, ip) for ip in ips]
        for hechos, futuro in enumerate(as_completed(futuros), 1):
            ip, metodo = futuro.result()
            if metodo:
                vivos[ip] = metodo
            if progreso:
                progreso(hechos, len(ips))

    # Equipos que bloquean ping y puertos igual quedan en la tabla ARP.
    arp = leer_tabla_arp()
    for ip in arp:
        if ipaddress.IPv4Address(ip) in red:
            vivos.setdefault(ip, "arp")

    propia = ip_local()
    dispositivos = [
        Dispositivo(ip=ip, mac=arp.get(ip), metodo=metodo, este_equipo=ip == propia)
        for ip, metodo in vivos.items()
    ]
    if resolver_nombres and dispositivos:
        with ThreadPoolExecutor(max_workers=min(32, len(dispositivos))) as ex:
            for d, nombre in zip(dispositivos, ex.map(nombre_host, [d.ip for d in dispositivos])):
                d.nombre_host = nombre
    dispositivos.sort(key=lambda d: ipaddress.IPv4Address(d.ip))
    return dispositivos

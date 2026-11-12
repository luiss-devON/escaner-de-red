"""Utilidades de red: IP local, red a escanear y direcciones MAC."""

from __future__ import annotations

import ipaddress
import re
import socket

MAX_HOSTS = 4096

_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_MAC = re.compile(r"\b([0-9A-Fa-f]{1,2}(?:[:-][0-9A-Fa-f]{1,2}){5})\b")


def ip_local() -> str:
    """IP de este equipo en la red local (no envía ningún paquete)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def red_por_defecto(ip: str | None = None) -> ipaddress.IPv4Network:
    """Red /24 que contiene la IP dada (o la IP local)."""
    return ipaddress.ip_network(f"{ip or ip_local()}/24", strict=False)


def parsear_red(texto: str) -> ipaddress.IPv4Network:
    try:
        red = ipaddress.ip_network(texto.strip(), strict=False)
    except ValueError:
        raise ValueError(f"red no válida: {texto!r} (ejemplo: 192.168.1.0/24)") from None
    if red.version != 4:
        raise ValueError("solo se admiten redes IPv4")
    if red.num_addresses > MAX_HOSTS:
        raise ValueError(f"la red es demasiado grande (máximo {MAX_HOSTS} direcciones, usa /20 o menor)")
    return red


def hosts(red: ipaddress.IPv4Network) -> list[str]:
    if red.num_addresses == 1:
        return [str(red.network_address)]
    return [str(h) for h in red.hosts()]


def normalizar_mac(texto: str) -> str:
    partes = re.split(r"[:-]", texto.strip())
    if len(partes) != 6 or not all(re.fullmatch(r"[0-9A-Fa-f]{1,2}", p) for p in partes):
        raise ValueError(f"MAC no válida: {texto!r}")
    return ":".join(p.zfill(2).upper() for p in partes)


def es_mac_de_equipo(mac: str) -> bool:
    """Descarta MAC vacías, de difusión y multicast."""
    primer = int(mac[:2], 16)
    return mac not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF") and not primer & 1


def es_mac_aleatoria(mac: str) -> bool:
    """MAC privada/aleatoria (bit 'administrada localmente'), típica de celulares."""
    return bool(int(mac[:2], 16) & 0b10)


def parsear_tabla_arp(texto: str) -> dict[str, str]:
    """Lee la salida de /proc/net/arp (Linux) o 'arp -a' (Windows, macOS) en cualquier idioma."""
    tabla: dict[str, str] = {}
    for linea in texto.splitlines():
        ip, mac = _IPV4.search(linea), _MAC.search(linea)
        if not ip or not mac:
            continue
        try:
            ipaddress.IPv4Address(ip.group(1))
            m = normalizar_mac(mac.group(1))
        except ValueError:
            continue
        if es_mac_de_equipo(m):
            tabla[ip.group(1)] = m
    return tabla

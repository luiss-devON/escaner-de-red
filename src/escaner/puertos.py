"""Escaneo de puertos TCP por conexión (no requiere administrador)."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

SERVICIOS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 135: "RPC de Windows", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB (carpetas compartidas)", 515: "Impresora (LPD)", 554: "RTSP (cámaras)",
    631: "IPP (impresora)", 993: "IMAPS", 995: "POP3S", 1433: "SQL Server", 1883: "MQTT",
    3306: "MySQL", 3389: "Escritorio remoto (RDP)", 5000: "UPnP / servidor web",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8000: "HTTP alternativo",
    8008: "HTTP alternativo", 8080: "HTTP alternativo", 8443: "HTTPS alternativo",
    8888: "HTTP alternativo", 9100: "Impresora (RAW)", 27017: "MongoDB",
    62078: "Sincronización de iPhone",
}

AVISOS = {
    21: "FTP envía usuario y contraseña sin cifrar.",
    23: "Telnet envía todo sin cifrar; desactívalo y usa SSH.",
    445: "Carpetas compartidas: revisa que pidan contraseña.",
    1883: "MQTT sin cifrar: cualquiera en la red podría leer los mensajes.",
    3389: "Escritorio remoto: usa contraseñas fuertes y no lo expongas a internet.",
    5900: "VNC suele tener contraseñas débiles.",
    6379: "Redis no pide contraseña por defecto.",
    27017: "MongoDB antiguo no pide contraseña por defecto.",
}


@dataclass
class PuertoAbierto:
    puerto: int
    servicio: str
    aviso: str | None = None


def parsear_puertos(texto: str) -> list[int]:
    """'comunes', '80', '1-1024' o combinaciones: '22,80,8000-8100'."""
    texto = texto.strip().lower()
    if texto == "comunes":
        return sorted(SERVICIOS)
    puertos: set[int] = set()
    try:
        for parte in filter(None, (p.strip() for p in texto.split(","))):
            if "-" in parte:
                ini, fin = (int(x) for x in parte.split("-", 1))
            else:
                ini = fin = int(parte)
            if not 1 <= ini <= fin <= 65535:
                raise ValueError
            puertos.update(range(ini, fin + 1))
    except ValueError:
        raise ValueError(f"puertos no válidos: {texto!r} (ejemplos: comunes, 80, 1-1024, 22,80,443)") from None
    if not puertos:
        raise ValueError("no se indicó ningún puerto")
    return sorted(puertos)


def puerto_abierto(ip: str, puerto: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((ip, puerto), timeout=timeout):
            return True
    except OSError:
        return False


def escanear_puertos(ip: str, puertos: list[int], timeout: float = 0.5, hilos: int = 200) -> list[PuertoAbierto]:
    with ThreadPoolExecutor(max_workers=max(1, min(hilos, len(puertos)))) as ex:
        estados = list(ex.map(lambda p: puerto_abierto(ip, p, timeout), puertos))
    return [
        PuertoAbierto(p, SERVICIOS.get(p, "desconocido"), AVISOS.get(p))
        for p, abierto in zip(puertos, estados)
        if abierto
    ]

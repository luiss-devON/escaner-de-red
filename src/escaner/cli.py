"""Interfaz de línea de comandos del escáner de red."""

from __future__ import annotations

import argparse
import os
import socket
import sys
import time
from pathlib import Path

from . import __version__
from .descubrimiento import descubrir
from .historial import Cambios, Historial
from .puertos import escanear_puertos, parsear_puertos
from .red import ip_local, parsear_red, red_por_defecto
from .reporte import a_csv, a_html, a_json, tabla

DATOS_POR_DEFECTO = Path.home() / ".escaner-red" / "dispositivos.json"


def _red(texto: str):
    try:
        return parsear_red(texto)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _puertos(texto: str) -> list[int]:
    try:
        return parsear_puertos(texto)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _segundos(minimo: float):
    def convertir(texto: str) -> float:
        try:
            valor = float(texto)
        except ValueError:
            valor = -1
        if valor < minimo:
            raise argparse.ArgumentTypeError(f"debe ser un número mayor o igual a {minimo}")
        return valor
    return convertir


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="escaner", description="Descubre qué dispositivos hay en tu red y qué puertos tienen abiertos.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--datos", type=Path, default=Path(os.environ.get("ESCANER_DATOS", DATOS_POR_DEFECTO)),
                   help="archivo JSON del historial de dispositivos")
    sub = p.add_subparsers(dest="comando", required=True, metavar="comando")

    sub.add_parser("info", help="muestra tu IP y la red que se escaneará")

    d = sub.add_parser("descubrir", help="lista los dispositivos conectados a la red")
    d.add_argument("--red", type=_red, help="red a escanear, ej. 192.168.1.0/24 (por defecto la tuya)")
    d.add_argument("--timeout", type=_segundos(0.1), default=1.0, help="segundos de espera por equipo (1)")
    d.add_argument("--sin-nombres", action="store_true", help="no buscar nombres de host (más rápido)")
    d.add_argument("--html", type=Path, help="guardar reporte HTML")
    d.add_argument("--json", type=Path, help="guardar resultado en JSON")
    d.add_argument("--csv", type=Path, help="guardar resultado en CSV")

    pu = sub.add_parser("puertos", help="busca puertos abiertos en un equipo")
    pu.add_argument("objetivo", help="IP o nombre del equipo")
    pu.add_argument("--puertos", type=_puertos, default="comunes", help="comunes | 80 | 1-1024 | 22,80,443")
    pu.add_argument("--timeout", type=_segundos(0.05), default=0.5)

    sub.add_parser("dispositivos", help="muestra todos los dispositivos vistos alguna vez")

    n = sub.add_parser("nombrar", help="pone un nombre fácil a un dispositivo")
    n.add_argument("identificador", help="MAC o IP del dispositivo")
    n.add_argument("alias", help='nombre, ej. "tele de la sala"')

    v = sub.add_parser("vigilar", help="escanea cada cierto tiempo y avisa si aparece un dispositivo nuevo")
    v.add_argument("--red", type=_red)
    v.add_argument("--cada", type=_segundos(10), default=300, help="segundos entre escaneos (300)")
    v.add_argument("--timeout", type=_segundos(0.1), default=1.0)
    return p


def _progreso(hechos: int, total: int) -> None:
    if sys.stderr.isatty():
        print(f"\r  Escaneando... {hechos}/{total}", end="" if hechos < total else "\n", file=sys.stderr, flush=True)


def _describir(e: dict) -> str:
    nombre = e.get("alias") or e.get("nombre_host") or "sin nombre"
    return f"{e.get('ip')}  {e.get('mac') or 'MAC desconocida'}  {nombre}"


def _mostrar_cambios(cambios: Cambios, total: int) -> None:
    if cambios.primer_escaneo:
        print(f"\nPrimer escaneo: {total} dispositivos guardados. Desde ahora te avisaré de los nuevos.")
        return
    for e in cambios.nuevos:
        print(f"\a⚠️  NUEVO dispositivo: {_describir(e)}")
    for e in cambios.desconectados:
        print(f"   Se desconectó: {_describir(e)}")
    if not cambios.nuevos:
        print("\n✅ Ningún dispositivo nuevo.")


def _escanear(args, historial: Historial):
    red = args.red or red_por_defecto()
    print(f"Escaneando {red} ...", file=sys.stderr)
    dispositivos = descubrir(red, timeout=args.timeout,
                             resolver_nombres=not getattr(args, "sin_nombres", False), progreso=_progreso)
    cambios = historial.registrar(dispositivos)
    historial.guardar()
    return red, dispositivos, cambios


def _guardar(ruta: Path, contenido: str) -> None:
    ruta.parent.mkdir(parents=True, exist_ok=True)
    ruta.write_text(contenido, encoding="utf-8")
    print(f"Guardado: {ruta}")


def main(argv: list[str] | None = None) -> int:
    for flujo in (sys.stdout, sys.stderr):
        if hasattr(flujo, "reconfigure"):
            flujo.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    historial = Historial(args.datos)
    if historial.aviso:
        print(historial.aviso, file=sys.stderr)

    if args.comando == "info":
        print(f"Tu IP local : {ip_local()}")
        print(f"Red         : {red_por_defecto()}")
        print(f"Historial   : {args.datos} ({len(historial.equipos)} dispositivos conocidos)")

    elif args.comando == "descubrir":
        red, dispositivos, cambios = _escanear(args, historial)
        print(f"\n{len(dispositivos)} dispositivos en {red}\n")
        print(tabla(dispositivos))
        _mostrar_cambios(cambios, len(dispositivos))
        if args.html:
            _guardar(args.html, a_html(dispositivos, str(red), cambios))
        if args.json:
            _guardar(args.json, a_json(dispositivos))
        if args.csv:
            _guardar(args.csv, a_csv(dispositivos))

    elif args.comando == "puertos":
        try:
            ip = socket.gethostbyname(args.objetivo)
        except OSError:
            print(f"Error: no se encontró el equipo {args.objetivo!r}", file=sys.stderr)
            return 1
        print(f"Revisando {len(args.puertos)} puertos de {ip} ...", file=sys.stderr)
        abiertos = escanear_puertos(ip, args.puertos, timeout=args.timeout)
        if not abiertos:
            print("No se encontraron puertos abiertos.")
        for a in abiertos:
            print(f"  {a.puerto:>5}/tcp  abierto  {a.servicio}")
            if a.aviso:
                print(f"         ⚠️  {a.aviso}")

    elif args.comando == "dispositivos":
        equipos = historial.lista()
        if not equipos:
            print("Aún no hay dispositivos. Ejecuta: escaner descubrir")
        for e in equipos:
            estado = "🟢" if e.get("en_linea") else "⚪"
            print(f"{estado} {_describir(e)}  (visto: {e.get('ultima_vez', '?')})")

    elif args.comando == "nombrar":
        if not historial.nombrar(args.identificador, args.alias):
            print(f"Error: no conozco el dispositivo {args.identificador!r}. Usa: escaner dispositivos", file=sys.stderr)
            return 1
        historial.guardar()
        print(f"Listo: {args.identificador} ahora se llama {args.alias!r}")

    elif args.comando == "vigilar":
        print(f"Vigilando la red cada {args.cada:g} s. Ctrl+C para salir.", file=sys.stderr)
        try:
            while True:
                _, dispositivos, cambios = _escanear(args, historial)
                print(f"[{time.strftime('%H:%M:%S')}] {len(dispositivos)} dispositivos")
                _mostrar_cambios(cambios, len(dispositivos))
                time.sleep(args.cada)
        except KeyboardInterrupt:
            print("\nVigilancia detenida.")
    return 0

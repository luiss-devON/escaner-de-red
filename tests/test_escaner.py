import io
import json
import socket
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from pathlib import Path
from unittest import mock

from escaner import descubrimiento
from escaner.cli import main
from escaner.descubrimiento import Dispositivo, descubrir, sondeo_tcp
from escaner.historial import Historial
from escaner.puertos import escanear_puertos, parsear_puertos
from escaner.red import (es_mac_aleatoria, es_mac_de_equipo, hosts, normalizar_mac,
                         parsear_red, parsear_tabla_arp, red_por_defecto)
from escaner.reporte import a_csv, a_html, a_json, tabla


def servidor():
    """Socket escuchando en un puerto libre de 127.0.0.1."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen()
    return s, s.getsockname()[1]


def puerto_cerrado():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    puerto = s.getsockname()[1]
    s.close()
    return puerto


class RedTest(unittest.TestCase):
    def test_red_por_defecto(self):
        self.assertEqual(str(red_por_defecto("192.168.1.37")), "192.168.1.0/24")

    def test_parsear_red(self):
        self.assertEqual(str(parsear_red("10.0.0.5/24")), "10.0.0.0/24")
        for malo in ("abc", "300.1.1.1/24", "::1/128", "10.0.0.0/8"):
            with self.subTest(malo=malo), self.assertRaises(ValueError):
                parsear_red(malo)

    def test_hosts(self):
        self.assertEqual(len(hosts(parsear_red("192.168.0.0/24"))), 254)
        self.assertEqual(hosts(parsear_red("192.168.0.9/32")), ["192.168.0.9"])

    def test_mac(self):
        self.assertEqual(normalizar_mac("a-b-c-d-e-f"), "0A:0B:0C:0D:0E:0F")
        self.assertEqual(normalizar_mac("aa:bb:cc:dd:ee:ff"), "AA:BB:CC:DD:EE:FF")
        for malo in ("", "aa:bb", "gg:bb:cc:dd:ee:ff", "aaa:bb:cc:dd:ee:ff"):
            with self.subTest(malo=malo), self.assertRaises(ValueError):
                normalizar_mac(malo)
        self.assertTrue(es_mac_aleatoria("DA:A1:19:00:00:01"))
        self.assertFalse(es_mac_aleatoria("00:1A:2B:3C:4D:5E"))
        self.assertFalse(es_mac_de_equipo("FF:FF:FF:FF:FF:FF"))
        self.assertFalse(es_mac_de_equipo("01:00:5E:00:00:FB"))
        self.assertFalse(es_mac_de_equipo("00:00:00:00:00:00"))


class ArpTest(unittest.TestCase):
    def test_linux(self):
        texto = (
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:01     *        wlan0\n"
            "192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        wlan0\n"
        )
        self.assertEqual(parsear_tabla_arp(texto), {"192.168.1.1": "AA:BB:CC:DD:EE:01"})

    def test_windows_espanol(self):
        texto = (
            "Interfaz: 192.168.1.5 --- 0xb\n"
            "  Dirección de Internet          Dirección física      Tipo\n"
            "  192.168.1.1           aa-bb-cc-dd-ee-01     dinámico\n"
            "  192.168.1.255         ff-ff-ff-ff-ff-ff     estático\n"
            "  224.0.0.251           01-00-5e-00-00-fb     estático\n"
        )
        self.assertEqual(parsear_tabla_arp(texto), {"192.168.1.1": "AA:BB:CC:DD:EE:01"})

    def test_macos(self):
        texto = "? (192.168.1.20) at 0:1a:2b:3c:4d:5e on en0 ifscope [ethernet]\n"
        self.assertEqual(parsear_tabla_arp(texto), {"192.168.1.20": "00:1A:2B:3C:4D:5E"})


class PuertosTest(unittest.TestCase):
    def test_parsear(self):
        self.assertEqual(parsear_puertos("80"), [80])
        self.assertEqual(parsear_puertos("22, 80,79-81"), [22, 79, 80, 81])
        self.assertIn(443, parsear_puertos("comunes"))
        for malo in ("", "0", "70000", "90-80", "abc", "1-2-3"):
            with self.subTest(malo=malo), self.assertRaises(ValueError):
                parsear_puertos(malo)

    def test_escanear_local(self):
        s, abierto = servidor()
        cerrado = puerto_cerrado()
        try:
            res = escanear_puertos("127.0.0.1", [abierto, cerrado], timeout=0.5)
        finally:
            s.close()
        self.assertEqual([r.puerto for r in res], [abierto])

    def test_aviso_telnet(self):
        with mock.patch("escaner.puertos.puerto_abierto", return_value=True):
            res = escanear_puertos("127.0.0.1", [23])
        self.assertEqual(res[0].servicio, "Telnet")
        self.assertIn("SSH", res[0].aviso)


class DescubrimientoTest(unittest.TestCase):
    def test_sondeo_tcp(self):
        s, puerto = servidor()
        try:
            self.assertTrue(sondeo_tcp("127.0.0.1", [puerto]))
        finally:
            s.close()

    def test_descubrir(self):
        s, puerto = servidor()
        try:
            with mock.patch.object(descubrimiento, "ping", return_value=False), \
                 mock.patch.object(descubrimiento, "leer_tabla_arp", return_value={}):
                res = descubrir(parsear_red("127.0.0.1/32"), resolver_nombres=False, puertos_sondeo=[puerto])
        finally:
            s.close()
        self.assertEqual([(d.ip, d.metodo) for d in res], [("127.0.0.1", "tcp")])

    def test_descubrir_usa_arp(self):
        with mock.patch.object(descubrimiento, "ping", return_value=False), \
             mock.patch.object(descubrimiento, "sondeo_tcp", return_value=False), \
             mock.patch.object(descubrimiento, "leer_tabla_arp",
                               return_value={"10.9.9.3": "AA:BB:CC:00:00:01", "172.16.0.1": "AA:BB:CC:00:00:02"}):
            res = descubrir(parsear_red("10.9.9.0/29"), resolver_nombres=False)
        self.assertEqual([(d.ip, d.mac, d.metodo) for d in res], [("10.9.9.3", "AA:BB:CC:00:00:01", "arp")])

    def test_ping_windows_inaccesible(self):
        # Windows responde con código 0 aunque el host no exista.
        r = mock.Mock(returncode=0, stdout=b"Reply from 192.168.1.5: Destination host unreachable.")
        with mock.patch("subprocess.run", return_value=r), mock.patch("shutil.which", return_value="ping"):
            self.assertFalse(descubrimiento.ping("192.168.1.77"))
        r.stdout = b"Respuesta desde 192.168.1.1: bytes=32 tiempo=2ms TTL=64"
        with mock.patch("subprocess.run", return_value=r), mock.patch("shutil.which", return_value="ping"):
            self.assertTrue(descubrimiento.ping("192.168.1.1"))


class HistorialTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ruta = Path(self.tmp.name) / "h.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_nuevos_y_desconectados(self):
        a = Dispositivo("192.168.1.2", "AA:00:00:00:00:01")
        b = Dispositivo("192.168.1.3", "AA:00:00:00:00:02")
        h = Historial(self.ruta)
        primero = h.registrar([a, b], datetime(2026, 1, 1))
        self.assertTrue(primero.primer_escaneo)
        self.assertEqual(primero.nuevos, [])
        h.guardar()

        h = Historial(self.ruta)
        c = Dispositivo("192.168.1.4")
        cambios = h.registrar([Dispositivo("192.168.1.2", "AA:00:00:00:00:01"), c])
        self.assertFalse(cambios.primer_escaneo)
        self.assertEqual([e["ip"] for e in cambios.nuevos], ["192.168.1.4"])
        self.assertEqual([e["mac"] for e in cambios.desconectados], ["AA:00:00:00:00:02"])
        # El desconectado no se vuelve a avisar.
        self.assertEqual(h.registrar([c]).desconectados[0]["mac"], "AA:00:00:00:00:01")

    def test_alias(self):
        h = Historial(self.ruta)
        h.registrar([Dispositivo("192.168.1.2", "AA:00:00:00:00:01")])
        self.assertTrue(h.nombrar("aa-00-00-00-00-01", "tele"))
        self.assertFalse(h.nombrar("192.168.1.99", "x"))
        self.assertFalse(h.nombrar("hola", "x"))
        h.guardar()
        d = Dispositivo("192.168.1.8", "AA:00:00:00:00:01")
        Historial(self.ruta).registrar([d])
        self.assertEqual(d.alias, "tele")
        h2 = Historial(self.ruta)
        self.assertTrue(h2.nombrar("192.168.1.2", "sala"))

    def test_archivo_danado(self):
        self.ruta.write_text("{no es json", encoding="utf-8")
        h = Historial(self.ruta)
        self.assertEqual(h.equipos, {})
        self.assertIsNotNone(h.aviso)
        self.assertTrue(self.ruta.with_suffix(".danado.json").exists())


class ReporteTest(unittest.TestCase):
    def setUp(self):
        self.ds = [
            Dispositivo("192.168.1.1", "00:1A:2B:3C:4D:5E", "router.lan", metodo="ping"),
            Dispositivo("192.168.1.7", "DA:A1:19:00:00:01", alias="<script>x</script>", metodo="arp", este_equipo=True),
        ]

    def test_tabla(self):
        t = tabla(self.ds)
        self.assertIn("router.lan", t)
        self.assertIn("(este equipo)", t)
        self.assertIn("MAC privada", t)

    def test_html_escapa(self):
        h = a_html(self.ds, "192.168.1.0/24")
        self.assertNotIn("<script>x", h)
        self.assertIn("&lt;script&gt;", h)

    def test_json_csv(self):
        datos = json.loads(a_json(self.ds))
        self.assertTrue(datos[1]["mac_aleatoria"])
        self.assertTrue(a_csv(self.ds).startswith("ip,mac,nombre_host,alias,metodo,mac_aleatoria,este_equipo\n"))


class CliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.datos = str(self.dir / "h.json")

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            codigo = main(["--datos", self.datos, *args])
        return codigo, out.getvalue(), err.getvalue()

    def test_info(self):
        codigo, out, _ = self.run_cli("info")
        self.assertEqual(codigo, 0)
        self.assertIn("/24", out)

    def test_puertos(self):
        s, puerto = servidor()
        try:
            codigo, out, _ = self.run_cli("puertos", "127.0.0.1", "--puertos", str(puerto))
        finally:
            s.close()
        self.assertEqual(codigo, 0)
        self.assertIn(f"{puerto}/tcp  abierto", out)

    def test_puertos_host_inexistente(self):
        codigo, _, err = self.run_cli("puertos", "no-existe.invalid")
        self.assertEqual(codigo, 1)
        self.assertIn("no se encontró", err)

    def test_descubrir_y_nombrar(self):
        falsos = [Dispositivo("192.168.50.2", "AA:00:00:00:00:01", metodo="ping")]
        html = self.dir / "r.html"
        with mock.patch("escaner.cli.descubrir", return_value=falsos):
            codigo, out, _ = self.run_cli("descubrir", "--red", "192.168.50.0/24", "--html", str(html))
        self.assertEqual(codigo, 0)
        self.assertIn("Primer escaneo", out)
        self.assertTrue(html.exists())

        self.assertEqual(self.run_cli("nombrar", "192.168.50.2", "impresora")[0], 0)
        self.assertEqual(self.run_cli("nombrar", "192.168.50.99", "x")[0], 1)
        self.assertIn("impresora", self.run_cli("dispositivos")[1])

        nuevos = falsos + [Dispositivo("192.168.50.3", "AA:00:00:00:00:02", metodo="ping")]
        with mock.patch("escaner.cli.descubrir", return_value=nuevos):
            _, out, _ = self.run_cli("descubrir", "--red", "192.168.50.0/24", "--sin-nombres")
        self.assertIn("NUEVO dispositivo: 192.168.50.3", out)

    def test_argumentos_invalidos(self):
        for args in (["descubrir", "--red", "abc"], ["puertos", "x", "--puertos", "0"], ["vigilar", "--cada", "1"]):
            with self.subTest(args=args), self.assertRaises(SystemExit):
                self.run_cli(*args)


if __name__ == "__main__":
    unittest.main()

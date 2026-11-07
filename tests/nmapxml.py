"""Generator de XML în stilul nmap, doar pentru teste.

IMPORTANT: fișierele produse aici sunt SINTETICE (construite de noi). Nu sunt
Validation Set-ul oficial. Validation Set-ul real se pune în fixtures/validation/
și e testat separat (tests/test_validation_set.py).
"""

from __future__ import annotations

from xml.sax.saxutils import quoteattr

NMAP_HEADER = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    "<!DOCTYPE nmaprun>\n"
    '<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>\n'
    "<!-- Nmap 7.94 scan initiated (sintetic) -->\n"
)


def port(
    number: int,
    proto: str = "tcp",
    state: str = "open",
    name: str | None = None,
    product: str | None = None,
    version: str | None = None,
    extrainfo: str | None = None,
    tunnel: str | None = None,
    title: str | None = None,
    title_output: str | None = None,
) -> str:
    attrs = []
    if name is not None:
        attrs.append(f"name={quoteattr(name)}")
    if product is not None:
        attrs.append(f"product={quoteattr(product)}")
    if version is not None:
        attrs.append(f"version={quoteattr(version)}")
    if extrainfo is not None:
        attrs.append(f"extrainfo={quoteattr(extrainfo)}")
    if tunnel is not None:
        attrs.append(f"tunnel={quoteattr(tunnel)}")
    service = f"<service {' '.join(attrs)} method=\"probed\" conf=\"10\"/>" if attrs else ""
    out = title_output if title_output is not None else title
    script = f'<script id="http-title" output={quoteattr(out)}/>' if out is not None else ""
    return (
        f'<port protocol="{proto}" portid="{number}">'
        f'<state state="{state}" reason="syn-ack"/>{service}{script}</port>'
    )


def host(
    ip: str,
    mac: str | None = None,
    vendor: str | None = None,
    hostname: str | None = None,
    ports: list[str] | None = None,
    status: str = "up",
) -> str:
    parts = [f'<host><status state="{status}" reason="arp-response"/>']
    parts.append(f'<address addr="{ip}" addrtype="ipv4"/>')
    if mac is not None:
        vend = f" vendor={quoteattr(vendor)}" if vendor is not None else ""
        parts.append(f'<address addr="{mac}" addrtype="mac"{vend}/>')
    if hostname is not None:
        parts.append(f'<hostnames><hostname name={quoteattr(hostname)} type="PTR"/></hostnames>')
    else:
        parts.append("<hostnames/>")
    if ports is not None:
        parts.append(
            '<ports><extraports state="closed" count="990"/>' + "".join(ports) + "</ports>"
        )
    parts.append("</host>")
    return "".join(parts)


def nmaprun(hosts: list[str], start: int | None = 1762500000) -> str:
    start_attr = f' start="{start}"' if start is not None else ""
    return (
        NMAP_HEADER
        + f'<nmaprun scanner="nmap" args="nmap -sS -sU -sV -oX x.xml 192.168.1.0/24"{start_attr} version="7.94">'
        + "".join(hosts)
        + '<runstats><finished time="1762500100"/></runstats></nmaprun>\n'
    )


# --------------------------------------------------------------------------- #
# Echivalente SINTETICE ale lui V1..V7 (aceeași structură ca în brief)
# --------------------------------------------------------------------------- #
def v1_home_basic() -> str:
    return nmaprun([
        host("192.168.1.1", "AA:00:00:00:00:01", "RouterCo", ports=[
            port(80, name="http", title="Router Login"),
            port(443, name="http", tunnel="ssl", title="Router Login"),  # HTTPS: nu e finding
        ]),
        host("192.168.1.20", "AA:00:00:00:00:02", "LaptopCo", ports=[]),
        host("192.168.1.30", "AA:00:00:00:00:03", "PhoneCo", ports=[]),
    ])


def v2_smart_home() -> str:
    return nmaprun([
        host("192.168.1.1", "AA:00:00:00:00:01", "RouterCo", ports=[
            port(80, name="http", title="Router Login"),
            port(1900, "udp", name="upnp"),
        ]),
        host("192.168.1.40", "AA:00:00:00:00:04", "CamCo", ports=[
            port(554, name="rtsp"),
            port(80, name="http", title="Camera Admin"),
        ]),
        host("192.168.1.41", "AA:00:00:00:00:05", "HubCo", hostname="smart-hub", ports=[
            port(1883, name="mqtt"),
        ]),
        host("192.168.1.50", "AA:00:00:00:00:06", "TvCo", ports=[
            port(8008, name="http", title="TV"),  # nu e în catalog
            port(8009, name="ajp13"),
        ]),
    ])


def v3_small_office() -> str:
    return nmaprun([
        host("192.168.1.10", "AA:00:00:00:00:07", "PrinterCo", ports=[
            port(9100, name="jetdirect"),
            port(631, name="ipp"),  # IPP: nu e finding
        ]),
        host("192.168.1.20", "AA:00:00:00:00:08", "NasCo", ports=[
            port(22, name="ssh", product="OpenSSH", version="8.9"),
            port(139, name="netbios-ssn"),
            port(445, name="microsoft-ds"),  # un singur SMB per dispozitiv, pe 445
        ]),
        host("192.168.1.30", "AA:00:00:00:00:09", "WinPcCo", ports=[
            port(3389, name="ms-wbt-server"),
        ]),
        host("192.168.1.40", "AA:00:00:00:00:0A", "LinuxCo", hostname="srv", ports=[
            port(22, name="ssh", product="OpenSSH", version="8.9"),
            port(3306, name="mysql"),
        ]),
    ])


def v4_legacy() -> str:
    return nmaprun([
        host("192.168.1.1", "AA:00:00:00:00:01", "OldRouterCo", ports=[
            port(23, name="telnet"),
            port(80, name="http", title="Router Setup"),
            port(161, "udp", name="snmp"),
        ]),
        host("192.168.1.60", "AA:00:00:00:00:0B", "OldServerCo", ports=[
            port(21, name="ftp", product="vsftpd", version="2.3.4"),
        ]),
        host("192.168.1.99", ports=[  # fără MAC, fără hostname, cu port deschis
            port(8080, name="http-proxy"),
        ]),
    ])


def v5_nonstandard_ports() -> str:
    return nmaprun([
        host("192.168.1.5", "AA:00:00:00:00:0C", "VendorC", ports=[port(2323, name="telnet")]),
        host("192.168.1.6", "AA:00:00:00:00:0D", "VendorD", ports=[
            port(8081, name="http", title="Admin Panel"),
        ]),
        host("192.168.1.7", "AA:00:00:00:00:0E", "VendorE", ports=[port(6380, name="redis")]),
        host("192.168.1.8", "AA:00:00:00:00:0F", "VendorF", ports=[
            port(8443, name="http", tunnel="ssl", title="Admin Panel"),
        ]),
        host("192.168.1.9", "AA:00:00:00:00:10", "VendorG", ports=[
            port(3306, state="filtered", name="mysql"),
        ]),
    ])


def v6a_before() -> str:
    return nmaprun([
        host("192.168.1.1", "AA:00:00:00:00:01", "RouterCo", ports=[
            port(80, name="http", title="Router Login"),
            port(1900, "udp", name="upnp"),
        ]),
        host("192.168.1.30", "AA:00:00:00:00:11", "OldBoxCo", ports=[port(23, name="telnet")]),
        host("192.168.1.20", "AA:00:00:00:00:02", "LaptopCo", ports=[]),
    ], start=1762500000)


def v6b_after() -> str:
    return nmaprun([
        host("192.168.1.1", "AA:00:00:00:00:01", "RouterCo", ports=[
            port(443, name="http", tunnel="ssl", title="Router Login"),
        ]),
        host("192.168.1.30", "AA:00:00:00:00:11", "OldBoxCo", ports=[]),
        host("192.168.1.20", "AA:00:00:00:00:02", "LaptopCo", ports=[]),
    ], start=1762503600)


def v7_broken() -> str:
    """V1 tăiat la jumătate: fișier trunchiat."""
    text = v1_home_basic()
    return text[: len(text) // 2]


SYNTHETIC_VALIDATION = {
    "V1_home_basic.xml": v1_home_basic,
    "V2_smart_home.xml": v2_smart_home,
    "V3_small_office.xml": v3_small_office,
    "V4_legacy.xml": v4_legacy,
    "V5_nonstandard_ports.xml": v5_nonstandard_ports,
    "V6a_before.xml": v6a_before,
    "V6b_after.xml": v6b_after,
    "V7_broken.xml": v7_broken,
}

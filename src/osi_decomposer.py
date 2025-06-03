from dataclasses import dataclass
from typing import Dict, Any, List
from scapy.all import IP, ICMP, Ether, hexdump
import json, time, textwrap, binascii
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from typer import *

@dataclass
class Layer:
    osi: int
    name: str
    fields: Dict[str, Any]
    payload: bytes

    def raw(self) -> bytes:
        hdr = self.fields.get("_bytes", b"")
        return hdr + self.payload

def build_layers(ip_addr: str, url: str) -> List[Layer]:

    app_msg = {
        "type": f"Pinging IP: {ip_addr} ({url})",
        "time": time.time(),
        "note": "NetViz Echo Request"
    }

    l7_bytes = json.dumps(app_msg).encode()
    l7 = Layer(7, "Application (JSON)", {
        "Content-Type": "application/json",
        "Content-Length": len(l7_bytes),
        "_bytes": l7_bytes[:0]
    }, l7_bytes)

    pres_hdr = b"\x75\x74\x66\x38"
    l6 = Layer(6, "Presentation (UTF-8)", {
        "encoding": "UTF-8",
        "_bytes"  : pres_hdr
    }, l7.raw())

    sess_id  = b"PINGSESSION\x00"
    l5 = Layer(5, "Session", {
        "session-id": sess_id.decode(errors='ignore'),
        "_bytes"    : sess_id
    }, l6.raw())

    scapy_icmp = ICMP(id=0XBEEF, seq=1)/l5.raw()
    icmp_bytes = bytes(scapy_icmp)
    l4 = Layer(4, "ICMP (Echo Request)", {
        **scapy_icmp.fields,
        "_bytes": icmp_bytes[:8]  # ICMP header is 8 bytes
    }, icmp_bytes[8:])

    scapy_ip = IP(dst=ip_addr, ttl=64)/bytes(l4.raw())
    ip_bytes = bytes(scapy_ip)
    l3 = Layer(3, "IPv4", {
        **scapy_ip.fields,
        "_bytes": ip_bytes[:20]  # Standard IPv4 header is 20 bytes (5 * 32-bit words)
    }, ip_bytes[20:])

    scapy_eth = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:00")/bytes(l3.raw())
    l2 = Layer(2, "Data Link (Ethernet II)", {
        **scapy_eth.fields,
        "_bytes": bytes(scapy_eth)[:14]
    }, bytes(scapy_eth.payload))

    bitstring = ''.join(f"{b:08b}" for b in l2.raw())
    pretty_bits = textwrap.fill(bitstring, 64)
    l1 =  Layer(1, "Physical (copper/fibre/coaxial)", {
        "encoding": "NRZ (std)",
        "length": len(bitstring),
        "_bytes": pretty_bits.encode()
    }, b"")

    return [l7, l6, l5, l4, l3, l2, l1]

def pretty_show(layers: List[any]):
    console = Console()
    palette = ["bright_blue", "bright_magenta", "bright_cyan", "bright_green", "bright_yellow", "bright_red", "bright_blue"]

    for index, layer in enumerate(layers):
        tab = Table.grid()
        for key, val in layer.fields.items():
            if key == "_scapy_pkt":
                continue
            tab.add_row(f"[bold]{key}[/]", str(val))
        hexbytes = hexdump(layer.raw(), dump=True)
        tab.add_row("[italic]bytes[/]", f"[{palette[index]}]{hexbytes}[/{palette[index]}]")
        console.print(Panel(tab, title=f"Layer {layer.osi}: {layer.name}", border_style=palette[index]))

def scapy_pkt_to_osi(pkt: scapy.all.packet) -> List[Layer]:

    pkt.show()
    layers_out = []
    previous_level_raw = bytes(pkt)

    if pkt.haslayer(Ether):
        typer.echo("Layer 2: Data Link (Ethernet II) exists in packet.")
        eth = pkt[Ether]
        eth_bytes, eth_payload = bytes(eth)[:14], bytes(eth)[14:]
        l2 = Layer(2, "Data Link (Ethernet II)", {
            "src": eth.src,
            "dst": eth.dst,
            "type": hex(eth.type),
            "_bytes": eth_bytes
        }, eth_payload)
        layers_out.append(l2)
        previous_level_raw = eth_payload

    else:
        typer.echo("Layer 2: Data Link (Ethernet II) does not exist in packet.")
        pass

    if pkt.haslayer(IP):
        typer.echo("Layer 3: Network (IPv4) exists in packet.")
        ip_layer = pkt[IP]
        ip_header_len = ip_layer.ihl * 4
        ip_bytes, ip_payload = bytes(ip_layer)[:ip_header_len], bytes(ip_layer)[ip_header_len:]
        l3 = Layer(3, "Network (IPv4)", {
            "src": ip_layer.src,
            "dst": ip_layer.dst,
            "ttl": ip_layer.ttl,
            "_bytes": ip_bytes
        }, ip_payload)
        layers_out.append(l3)
        previous_level_raw = ip_payload
    else:
        typer.echo("Layer 3: Network (IPv4) does not exist in packet.")
        pass

    if pkt.haslayer(TCP):
        typer.echo("Layer 4: Transport (TCP) exists in packet.")
        tcp_layer = pkt[TCP]
        tcp_hdr_len = tcp_layer.dataofs * 4
        tcp_bytes, tcp_payload = bytes(tcp_layer)[:tcp_hdr_len], bytes(tcp_layer)[tcp_hdr_len:]
        flags_str   = f"{tcp_layer.flags:08b}"
        l4 = Layer(4, "Transport (TCP)", {
            "src": tcp_layer.sport,
            "dst": tcp_layer.dport,
            "flags": flags_str,
            "seq": tcp_layer.seq,
            "ack": tcp_layer.ack,
            "window": tcp_layer.window,
            "_bytes": tcp_bytes
        }, tcp_payload)
        layers_out.append(l4)
        previous_level_raw = tcp_payload
    else:
        # VERY HIGHLY UNLIKELY
        typer.echo("Layer 4: Transport (TCP) does not exist in packet.")
        pass
    
    if hasattr(pkt, "load"):
        app_data = pkt.load

        l7 = Layer(
            7, "Application (HTTP?)",
            {"_bytes": b""},
            app_data
        )
        l6 = Layer(
            6, "Presentation",
            {"_bytes": b"\x75\x74\x66\x38"},  # "utf8" marker
            l7.raw()
        )
        sess = b"HTTPSESSION\x00"
        l5 = Layer(
            5, "Session",
            {"_bytes": sess},
            l6.raw()
        )
        layers_out.append(l5)
        layers_out.append(l6)
        layers_out.append(l7)
    else:
        typer.echo("Layer 7: Application (HTTP?) does not exist in packet.")
        pass

    final_bytes = layers_out[-1].raw() if layers_out else bytes(pkt)
    bitstring = ''.join(f"{b:08b}" for b in final_bytes)
    pretty_bits = textwrap.fill(bitstring, 64)
    l1 = Layer(1, "Physical (copper/fibre/coaxial)", {
        "encoding": "NRZ (std)",
        "length": len(bitstring),
        "_bytes": pretty_bits.encode()
    }, b"")
    layers_out.append(l1)
    
    # Sort from top(L7)→bottom(L1)
    layers_out.sort(key=lambda x: x.osi, reverse=True)
    return layers_out
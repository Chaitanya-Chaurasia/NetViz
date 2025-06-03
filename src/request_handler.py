from scapy.all import IP, TCP, Raw, send, sr1, sniff
from osi_decomposer import scapy_pkt_to_osi, pretty_show
import json

def request_flow(ip: str = "127.0.0.1", port: int = 5000, path: str = "/get", method: str = "GET", data=None):
    if data is None:
        data = {}

    body = json.dumps(data).encode() if method.upper() == "POST" else b""
    req_payload = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {ip}:{port}\r\n"
        f"User-Agent: RealScapy/1.0\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body

    captured_pkts = []

    def capture_callback(pkt):
        if pkt.haslayer(TCP) and (pkt[IP].src == ip or pkt[IP].dst == ip):
            captured_pkts.append(pkt)
            print(f"Captured packet: {pkt.summary()}")

    from threading import Thread
    
    sniffer = Thread(target=lambda: sniff(
        iface="Software Loopback Interface 1",
        filter=f"tcp port {port} and host {ip}",
        prn=capture_callback,
        store=False,
        timeout=10
    ))
    sniffer.start()
    
    import time
    time.sleep(1)
    
    try:
        print(f"Sending SYN to {ip}:{port}")
        syn_pkt = IP(dst=ip)/TCP(sport=12345, dport=port, flags="S", seq=1000)
        synack = sr1(syn_pkt, timeout=5, verbose=0)
        
        if not synack:
            print(f"[!] No response to SYN from {ip}:{port}")
            return
            
        print(f"Received SYN-ACK from {ip}:{port}")
        
        ack_pkt = IP(dst=ip)/TCP(
            sport=synack.dport,
            dport=synack.sport,
            flags="A",
            seq=synack.ack,
            ack=synack.seq + 1
        )
        send(ack_pkt, verbose=0)
        print("Sent ACK")
        
        psh_pkt = IP(dst=ip)/TCP(
            sport=synack.dport,
            dport=synack.sport,
            flags="PA",
            seq=synack.ack,
            ack=synack.seq + 1
        )/req_payload
        
        send(psh_pkt, verbose=0)
        print("Sent HTTP request")
        
        fin_pkt = IP(dst=ip)/TCP(
            sport=synack.dport,
            dport=synack.sport,
            flags="FA",
            seq=psh_pkt.seq + len(req_payload) if 'psh_pkt' in locals() else synack.ack,
            ack=synack.seq + 1
        )
        send(fin_pkt, verbose=0)
        print("Sent FIN-ACK")
        
        last_ack = IP(dst=ip)/TCP(
            sport=synack.dport,
            dport=synack.sport,
            flags="A",
            seq=fin_pkt.seq + 1,
            ack=fin_pkt.ack + 1
        )
        send(last_ack, verbose=0)
        print("Sent final ACK")
        
    except Exception as e:
        print(f"Error during TCP communication: {e}")
    
    sniffer.join(timeout=5)
    
    print(f"\nCaptured {len(captured_pkts)} packets")
    captured_pkts.sort(key=lambda x: x.time)

    for index, pkt in enumerate(captured_pkts):
        if pkt.haslayer(TCP):
            info = []
            if pkt[TCP].flags & 0x02: info.append("SYN")
            if pkt[TCP].flags & 0x10: info.append("ACK")
            if pkt[TCP].flags & 0x01: info.append("FIN")
            if pkt[TCP].flags & 0x08: info.append("PSH")
            if pkt[TCP].flags & 0x04: info.append("RST")
            
            flag_str = "+".join(info) if info else "[no flags]"
            print(f"\nPacket #{index} - {pkt.summary()}")
            print(f"Flags: {flag_str}")
            
            try:
                layers = scapy_pkt_to_osi(pkt)
                if layers:
                    pretty_show(layers)
            except Exception as e:
                print(f"Error processing packet layers: {e}")
    
    return captured_pkts
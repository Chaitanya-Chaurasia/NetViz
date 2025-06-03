from dataclasses import dataclass
from typing import Dict, Any, List
from scapy.all import IP, ICMP, Ether, hexdump

@dataclass
class Layer:
    osi: int
    name: str
    fields: Dict[str, Any]
    payload: bytes

    def raw(self) -> bytes:
        header = self.fields.get("_bytes", b"")
        return header + self.payload

def build_layers(dst_ip: str) -> List[Layer]:
    
    app_msg = {
        "type": "Ping-Demo",
    }


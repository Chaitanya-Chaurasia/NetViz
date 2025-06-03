from layers import build_layers, pretty_show

def trace_dns(ip_addr: str, url: str):
    if not url and ip_addr:
        return
    
def packet_encapsulation(ip_addr: str, url: str, show_layers: bool = True):
    if not url and ip_addr:
        return
    
    pretty_show(build_layers(ip_addr, url))


def trace_route(ip_addr: str, max_hops: int = 30):
    if not url and ip_addr:
        return

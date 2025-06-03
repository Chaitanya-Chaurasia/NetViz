from osi_decomposer import build_layers, pretty_show
from request_handler import request_flow

def trace_dns(ip_addr: str, url: str):
    if not url and ip_addr:
        return
    
def packet_encapsulation(ip_addr: str, url: str, show_layers: bool = True):
    if not url and ip_addr:
        return
    
    pretty_show(build_layers(ip_addr, url))


def trace_geo_route(url: str, ip_addr: str, max_hops: int = 30):
    if not url and ip_addr:
        return

def request_flow_handler(ip_addr: str, port: int = 5000, path: str = "/get", method: str = "GET", data = None):

    return request_flow(ip_addr, port, path, data = data, method = method)
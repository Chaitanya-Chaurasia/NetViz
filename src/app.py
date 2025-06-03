import socket, typer
from rich.progress import track
from method_callback import packet_encapsulation, trace_dns, trace_geo_route, request_flow_handler

help_str = "NetViz - Network Visualizer\n Usage: netviz [OPTIONS]"

app = typer.Typer(help = help_str)

"""
    Command: netviz dnsresolve <url>
    @params: url
    @description: Resolves the DNS name (stub + recursive) of the given URL
"""
@app.command()
def dnsresolve(url: str):
    print("TELEMETRY: Performing a complete DNS resolution (stub + recursive)")
    if not url:
        typer.echo("Please provide a URL")
        return
    
    try:
        target_ip = socket.gethostbyname(url)
        typer.echo(f"Resolved IP: {target_ip}")
    except socket.gaierror:
        typer.echo("Failed to resolve the URL. Please make sure the URL is valid!")
        return
    
    typer.echo("\nTracing DNS...")
    trace_dns(target_ip, url)

"""
    Command: netviz visualize <url>
    @params: url
    @description: Visualizes the packets of the given URL in 7 OSI layers
"""
@app.command()
def visualize(url: str):
    
    print("TELEMETRY: Performing packet encapsulation and visualization")
    if not url:
        typer.echo("Please provide a URL")
        return
    
    try:
        target_ip = socket.gethostbyname(url)
        typer.echo(f"Resolved IP: {target_ip}")
    except socket.gaierror:
        typer.echo("Failed to resolve the URL. Please make sure the URL is valid!")
        return
    
    typer.echo("\nTracing DNS...")
    trace_dns(target_ip, url)
    
    typer.echo("\nVisualizing packets...")
    packet_encapsulation(target_ip, url)

"""
    Command: netviz traceroute <url>
    @params: url
    @description: A complete trace -> DNS resolution + Packet Visualization + GeoTracing
"""
@app.command()
def traceroute(url: str, method: str, show_layers: bool = True, max_hops: int = 30):

    print("TELEMETRY: Performing a complete trace: DNS resolution + Packet Visualization + GeoTracing")
    if not url:
        typer.echo("Please provide a URL")
        return
    
    if not show_layers:
        typer.echo("@param show_layers is defaulting to True.")

    if not max_hops:
        typer.echo("@param max_hops is defaulting to 30.")

    if not method:
        typer.echo("@param method is defaulting to GET.")
    
    try:
        target_ip = socket.gethostbyname(url)
        typer.echo(f"Resolved IP: {target_ip}")
    except socket.gaierror:
        typer.echo("Failed to resolve the URL. Please make sure the URL is valid!")
        return
    
    typer.echo("\nTracing DNS...")
    trace_dns(target_ip, url)
    
    typer.echo("\nVisualizing packets and breaking them into OSI...")
    try:
        path = "/" + "/".join(url.split("/")[3:]) if "//" in url else "/"
        if method.upper() == "POST":
            data = {"key": "value"}
        request_flow_handler(ip_addr=target_ip, path=path, method=method, data=data)
        typer.echo("\nRequest flow completed successfully.")
    except Exception as e:
        typer.echo(f"Error during packet visualization: {str(e)}")

    typer.echo("\nTracing route...")
    trace_geo_route(url, target_ip, max_hops)

if __name__ == "__main__":
    app()
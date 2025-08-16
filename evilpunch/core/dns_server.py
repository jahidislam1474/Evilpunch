import socket
import threading
from typing import Optional, Dict, Any
from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, A

# --- COLORS ---
ANSI_GREEN = "\033[92m"
ANSI_RESET = "\033[0m"

# --- CONFIGURATION ---
# The IP address of the machine running this DNS server and the HTTP proxy.
# Use your server's public IP address.
PROXY_IP = "127.0.0.1"
# The domain you want to intercept. Add a trailing dot.
TARGET_DOMAIN = "fluxxset.com."
# The port this DNS server will listen on. DNS defaults to port 53.
DNS_PORT = 53
# ---------------------

_server_thread: Optional[threading.Thread] = None
_server_socket: Optional[socket.socket] = None
_stop_event: Optional[threading.Event] = None
_status: Dict[str, Any] = {"running": False, "port": None, "error": None}


def handle_dns_request(data, addr):
    """
    Parses a DNS request and returns a crafted or forwarded response.
    """
    request = DNSRecord.parse(data)
    qname = str(request.q.qname)

    # Check if the query is for our target domain
    if qname.endswith(TARGET_DOMAIN):
        print(f"[{addr[0]}] -> Intercepted DNS query for: {qname}")
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
                          q=request.q)
        reply.add_answer(RR(qname, A, rdata=A(PROXY_IP), ttl=60))
        return reply.pack()
    else:
        # For all other domains, forward the request to a real DNS server
        print(f"[{addr[0]}] -> Forwarding DNS query for: {qname}")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(data, ('8.8.8.8', 53))
            response_data, _ = sock.recvfrom(512)
            sock.close()
            return response_data
        except Exception as e:
            print(f"Error forwarding DNS query: {e}")
            return None

def _serve_loop(port: int, stop_event: threading.Event) -> None:
    global _server_socket, _status
    try:
        _server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _server_socket.bind(("0.0.0.0", port))
        _server_socket.settimeout(0.5)
        _status.update({"running": True, "port": port, "error": None})
        print(f"================================================")
        print(f"{ANSI_GREEN}[dns] DNS server running on 0.0.0.0:{port}...{ANSI_RESET}")
        print(f"================================================")
        while not stop_event.is_set():
            try:
                data, addr = _server_socket.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                # Socket closed during stop
                break
            response = handle_dns_request(data, addr)
            if response:
                try:
                    _server_socket.sendto(response, addr)
                except OSError:
                    break
    except Exception as e:
        _status.update({"running": False, "error": str(e)})
        print(f"[dns] Server error: {e}")
    finally:
        try:
            if _server_socket:
                _server_socket.close()
        finally:
            _server_socket = None
            _status["running"] = False


def start_dns_server(port: int = DNS_PORT, *, proxy_ip: Optional[str] = None, target_domain: Optional[str] = None) -> Dict[str, Any]:
    global _server_thread, _stop_event, PROXY_IP, TARGET_DOMAIN, DNS_PORT
    if proxy_ip:
        PROXY_IP = proxy_ip
    if target_domain:
        TARGET_DOMAIN = target_domain if target_domain.endswith('.') else f"{target_domain}."
    DNS_PORT = port
    if _server_thread and _server_thread.is_alive():
        return {"ok": True, "message": "DNS server already running.", "status": get_status()}
    _stop_event = threading.Event()
    _server_thread = threading.Thread(target=_serve_loop, args=(port, _stop_event), daemon=True)
    _server_thread.start()
    return {"ok": True, "message": "DNS server starting.", "status": get_status()}


def stop_dns_server() -> Dict[str, Any]:
    global _stop_event, _server_thread, _server_socket
    if not (_server_thread and _server_thread.is_alive()):
        return {"ok": True, "message": "DNS server not running.", "status": get_status()}
    if _stop_event:
        _stop_event.set()
    try:
        if _server_socket:
            _server_socket.close()
    except Exception:
        pass
    _server_thread.join(timeout=2.0)
    return {"ok": True, "message": "DNS server stopped.", "status": get_status()}


def restart_dns_server(port: Optional[int] = None) -> Dict[str, Any]:
    if get_status().get("running"):
        stop_dns_server()
    return start_dns_server(port or DNS_PORT)


def get_status() -> Dict[str, Any]:
    return {
        "running": bool(_server_thread and _server_thread.is_alive() and _status.get("running")),
        "port": _status.get("port") or DNS_PORT,
        "error": _status.get("error"),
    }

if __name__ == "__main__":
    # Keep CLI behavior for manual runs
    start_dns_server(DNS_PORT)
    try:
        while True:
            pass
    except KeyboardInterrupt:
        stop_dns_server()
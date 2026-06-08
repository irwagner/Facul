"""Probe pa.megaslott.com — painel de agentes do operador central."""
import gzip
import socket
import urllib.request

ip = "18.228.48.152"
for port in (80, 443):
    try:
        with socket.create_connection((ip, port), timeout=5):
            print(f"  {ip}:{port} ABERTA")
    except OSError as e:
        print(f"  {ip}:{port} {type(e).__name__}: {e}")

for url in ("https://pa.megaslott.com/", "http://pa.megaslott.com/"):
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0", "Accept-Encoding": "gzip"},
        )
        with urllib.request.urlopen(req, timeout=12) as r:
            body = r.read()
            if r.headers.get("content-encoding") == "gzip":
                body = gzip.decompress(body)
            server = r.headers.get("Server")
            via = r.headers.get("Via")
            ctype = r.headers.get("Content-Type")
            print(f"\n  === {url} ===")
            print(f"  status={r.status} size={len(body)}")
            print(f"  server={server}  via={via}  ctype={ctype}")
            print(f"  body[:400]:\n  {body[:400].decode(errors='replace')}")
    except Exception as e:
        print(f"\n  {url} ERR: {type(e).__name__}: {e}")

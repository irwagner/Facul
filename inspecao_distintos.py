"""
Inspeciona os 3 paths que retornaram conteudo distinto da SPA:
    /robots.txt, /manifest.json, /japi/
em ds. e m.

Tambem testa o range 18.161.205.x para identificar se eh CloudFront
(via reverse DNS / ASN) e analisa headers comparados com 18.64.207.x.
"""
from __future__ import annotations

import gzip
import json
import socket
import sys
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"


def fetch(url: str, *, timeout: float = 15.0) -> tuple[int, dict, bytes]:
    req = Request(url, headers={"User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "gzip"})
    with urlopen(req, timeout=timeout) as resp:
        body = resp.read()
        if resp.headers.get("content-encoding") == "gzip":
            body = gzip.decompress(body)
        return resp.status, dict(resp.getheaders()), body


def banner(t: str) -> None:
    print(f"\n{'=' * 70}\n  {t}\n{'=' * 70}")


def show_response(url: str) -> dict:
    print(f"\n  -> {url}")
    try:
        status, headers, body = fetch(url)
    except Exception as exc:
        print(f"     ERRO: {exc}")
        return {"url": url, "error": str(exc)}
    print(f"     status: {status}   bytes: {len(body)}")
    for h in ("server", "content-type", "via", "x-amz-cf-id", "x-amz-cf-pop",
              "x-cache", "set-cookie", "x-powered-by", "strict-transport-security",
              "content-security-policy", "x-frame-options"):
        value = headers.get(h) or headers.get(h.title()) or headers.get(h.upper())
        if value:
            print(f"     {h}: {value[:120]}")
    body_preview = body[:600].decode("utf-8", errors="replace")
    print(f"     body[0:600]:\n{body_preview}")
    return {
        "url": url,
        "status": status,
        "size": len(body),
        "headers": headers,
        "body_text": body.decode("utf-8", errors="replace"),
    }


def reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


def main() -> None:
    out: dict = {}

    banner("PATHS DISTINTOS DA SPA (conteudo real)")
    out["robots_ds"] = show_response("https://ds.amizade777.com/robots.txt")
    out["robots_m"] = show_response("https://m.amizade777.com/robots.txt")
    out["manifest_ds"] = show_response("https://ds.amizade777.com/manifest.json")
    out["manifest_m"] = show_response("https://m.amizade777.com/manifest.json")
    out["japi_ds"] = show_response("https://ds.amizade777.com/japi/")
    out["japi_m"] = show_response("https://m.amizade777.com/japi/")

    banner("DETALHES DOS HEADERS DA HOME (para comparar via vs cloudfront)")
    out["home_ds"] = show_response("https://ds.amizade777.com/")
    out["home_m"] = show_response("https://m.amizade777.com/")

    banner("REVERSE DNS DOS IPs DE m.amizade777.com")
    for ip in ["18.161.205.121", "18.161.205.55", "18.161.205.56", "18.161.205.69"]:
        rdns = reverse_dns(ip)
        print(f"  {ip} -> {rdns}")
        out.setdefault("rdns_m", {})[ip] = rdns

    banner("REVERSE DNS DOS IPs DE ds.amizade777.com")
    for ip in ["18.64.207.110", "18.64.207.51", "18.64.207.79", "18.64.207.87"]:
        rdns = reverse_dns(ip)
        print(f"  {ip} -> {rdns}")
        out.setdefault("rdns_ds", {})[ip] = rdns

    # AWS publica os ranges em https://ip-ranges.amazonaws.com/ip-ranges.json
    # Vamos buscar e classificar.
    banner("CLASSIFICACAO POR ip-ranges.amazonaws.com")
    try:
        _, _, body = fetch("https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=30)
        data = json.loads(body.decode("utf-8"))
    except Exception as exc:
        print(f"  ERRO ao buscar ip-ranges: {exc}")
        data = {"prefixes": []}

    import ipaddress as ipa
    targets = [
        "18.64.207.51", "18.64.207.79", "18.64.207.87", "18.64.207.110",
        "18.161.205.55", "18.161.205.56", "18.161.205.69", "18.161.205.121",
    ]
    classification = {}
    for ip in targets:
        addr = ipa.ip_address(ip)
        matches = []
        for entry in data.get("prefixes", []):
            try:
                if addr in ipa.ip_network(entry["ip_prefix"], strict=False):
                    matches.append(f"{entry.get('service')}/{entry.get('region')}")
            except ValueError:
                continue
        if not matches:
            print(f"  {ip}: nao classificado pela AWS")
        else:
            print(f"  {ip}: {' | '.join(matches)}")
        classification[ip] = matches
    out["aws_classification"] = classification

    Path("inspecao_distintos.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    print("\n  Resultado salvo em inspecao_distintos.json")


if __name__ == "__main__":
    main()

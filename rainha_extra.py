"""
Recon extra do rainha777slots.com:
  1. Procura path real do WebSocket no bundle do ds.
  2. Scan completo do pa. (painel de afiliados?) e do m.
  3. Comparativo SHA dos bundles entre amizade777 e rainha777slots
  4. Tenta acessar api.rainha777slots.com via diferentes portas/hosts
  5. Captura primeiro frame do WS no path correto
"""
from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import re
import socket
import sys
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from toolkit.discovery import ws_inspector

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"


def fetch(url, *, method="GET", headers=None, timeout=15.0):
    h = {"User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "gzip"}
    if headers:
        h.update(headers)
    req = Request(url, method=method, headers=h)
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            if resp.headers.get("content-encoding") == "gzip":
                raw = gzip.decompress(raw)
            return resp.status, dict(resp.getheaders()), raw
    except HTTPError as exc:
        try:
            raw = exc.read()
        except Exception:
            raw = b""
        return exc.code, dict(exc.headers or {}), raw
    except Exception as exc:
        return None, {}, str(exc).encode()


def banner(t):
    print(f"\n{'=' * 70}\n  {t}\n{'=' * 70}")


# ----------------------------------------------------------------------
# 1. Path real do WebSocket
# ----------------------------------------------------------------------

def step_ws_path():
    banner("[1/5] PATH REAL DO WEBSOCKET (ds.rainha777slots.com)")
    bundles_dir = ROOT / "bundles"
    targets = [f for f in bundles_dir.iterdir()
               if f.name.startswith("ds.rainha777slots.com_") and f.suffix == ".js"]
    print(f"  bundles candidatos: {len(targets)}")

    ws_paths = set()
    ws_urls = set()
    for f in targets:
        text = f.read_text(encoding="utf-8", errors="replace")
        # ws path simples
        for m in re.findall(r'["\'](/websocket\d{0,3}[a-zA-Z0-9_\-/]*)["\']', text):
            ws_paths.add(m)
        # full ws urls
        for m in re.findall(r"wss?://[a-zA-Z0-9\-\.]+(?::\d+)?/[a-zA-Z0-9_\-/]*", text):
            ws_urls.add(m)
        # Tambem buscar uso de "WebSocket(" com argumento string
        for m in re.findall(r'(?:new\s+WebSocket|WebSocket)\s*\(\s*["\']([^"\']+)["\']', text):
            if "ws" in m or "/" in m:
                ws_urls.add(m)
    print(f"  paths ws candidatos: {sorted(ws_paths)}")
    print(f"  urls ws candidatos: {sorted(ws_urls)}")
    
    # Probar todos os paths candidatos pra ver qual responde 101
    candidate_paths = list(ws_paths) + ["/websocket6", "/websocket7", "/websocket8",
                                         "/websocket9", "/websocket10", "/ws", "/wss",
                                         "/socket", "/socket.io", "/notice", "/notify"]
    candidate_paths = sorted(set(candidate_paths))
    print(f"\n  testando {len(candidate_paths)} paths via HTTP upgrade:")

    out = []
    for p in candidate_paths:
        status, headers, body = fetch(f"https://ds.rainha777slots.com{p}",
                                       headers={
                                           "Upgrade": "websocket",
                                           "Connection": "Upgrade",
                                           "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                                           "Sec-WebSocket-Version": "13",
                                       })
        if status is None:
            continue
        text = body[:80].decode("utf-8", errors="replace").replace("\n", " ")
        marker = ""
        if status == 101:
            marker = " <-- WS UP!"
        elif status == 426:
            marker = " <-- precisa upgrade"
        elif status == 400 and "Upgrade" in str(headers):
            marker = " <-- pediu upgrade"
        print(f"    {status:>3} {p:<25s} {text[:60]}{marker}")
        out.append({"path": p, "status": status, "headers": headers, "body": text[:200]})
    return {"candidate_paths": sorted(ws_paths), "candidate_urls": sorted(ws_urls), "probes": out}


# ----------------------------------------------------------------------
# 2. Scan focado em pa. e m.
# ----------------------------------------------------------------------

def step_pa_and_m():
    banner("[2/5] PROBE FOCADO EM pa. e m. (rainha777slots)")
    out = {}
    for host in ("pa.rainha777slots.com", "m.rainha777slots.com"):
        print(f"\n  --- {host} ---")
        # 1. home
        s, h, b = fetch(f"https://{host}/")
        title = ""
        if b:
            m = re.search(rb"<title[^>]*>([^<]+)</title>", b, re.I)
            if m:
                title = m.group(1).decode(errors="replace")
        print(f"    home: status={s} bytes={len(b)} title={title!r}")
        # 2. manifest
        s2, _, b2 = fetch(f"https://{host}/manifest.json")
        if s2 == 200 and b2:
            try:
                obj = json.loads(b2.decode())
                print(f"    manifest: name={obj.get('name')!r}")
            except Exception:
                pass
        # 3. paths interessantes
        for p in ("/japi/", "/japi/user/game/getGameList", "/japi/admin",
                  "/japi/system/admin", "/japi/user/list", "/japi/operator",
                  "/admin/login", "/painel", "/panel", "/affiliate",
                  "/agent", "/dashboard", "/login", "/login.html"):
            sp, _, bp = fetch(f"https://{host}{p}", timeout=8)
            if sp is None:
                continue
            text = bp[:120].decode("utf-8", errors="replace").replace("\n", " ")
            interesting = sp not in (404, 405) and "404 NOT_FOUND" not in text
            mark = "  <--" if interesting else ""
            print(f"    {sp:>3} {len(bp):>5}b  {p:<32s}  {text[:80]}{mark}")
        out[host] = {"status": s, "title": title}
    return out


# ----------------------------------------------------------------------
# 3. Comparativo SHA dos bundles
# ----------------------------------------------------------------------

def step_compare_bundles():
    banner("[3/5] COMPARATIVO DE BUNDLES — amizade777 vs rainha777slots")
    bundles = ROOT / "bundles"
    by_name = {}
    for f in bundles.iterdir():
        if not f.suffix == ".js":
            continue
        # nome de bundle = parte depois do segundo "_" ou ".js"
        # ex.: ds.amizade777.com_index.76929613.js -> base=index
        base = f.name.split("_", 1)[1].split(".")[0]
        sha = hashlib.sha256(f.read_bytes()).hexdigest()[:16]
        by_name.setdefault(base, []).append({
            "file": f.name, "sha": sha, "size": f.stat().st_size,
        })
    out = []
    for base, items in sorted(by_name.items()):
        if len(items) < 2:
            continue
        shas = {it["sha"] for it in items}
        same = len(shas) == 1
        marker = " <-- IDENTICO" if same else ""
        print(f"\n  === {base}{marker}")
        for it in items:
            print(f"    {it['file']:<55s} sha={it['sha']:16s} size={it['size']:,}")
        out.append({"base": base, "identical": same, "files": items})
    return out


# ----------------------------------------------------------------------
# 4. api.rainha777slots em portas alternativas
# ----------------------------------------------------------------------

def step_api_ports():
    banner("[4/5] api.rainha777slots.com EM PORTAS ALTERNATIVAS")
    try:
        ip = socket.gethostbyname("api.rainha777slots.com")
        print(f"  api.rainha777slots.com -> {ip}")
    except OSError as exc:
        print(f"  erro de DNS: {exc}")
        return {"error": "dns"}
    out = {"ip": ip, "ports": {}}
    for p in (80, 443, 3000, 3001, 5000, 8000, 8080, 8443, 8888, 9000, 9090):
        try:
            with socket.create_connection((ip, p), timeout=3):
                print(f"    {p:>5}/tcp ABERTA")
                out["ports"][p] = "open"
        except OSError as exc:
            out["ports"][p] = f"refused ({exc.__class__.__name__})"
    # Tambem testa Host header tricks com IP
    print("\n  HTTP em api.rainha777slots.com (porta 443) com Host headers:")
    for host in ("api.rainha777slots.com", "rainha777slots.com",
                 "ds.rainha777slots.com", "pa.rainha777slots.com",
                 "internal.rainha777slots.com", "admin.rainha777slots.com"):
        for scheme in ("https", "http"):
            url = f"{scheme}://api.rainha777slots.com/"
            s, h, b = fetch(url, headers={"Host": host}, timeout=8)
            if s:
                text = b[:100].decode("utf-8", errors="replace").replace("\n", " ")
                print(f"    Host={host:<35s} {scheme:5s} {s:>3} {text[:70]}")
    return out


# ----------------------------------------------------------------------
# 5. WebSocket capture (depois de descobrir o path certo)
# ----------------------------------------------------------------------

async def capture_ws(host, path):
    import websockets
    try:
        async with websockets.connect(
            f"wss://{host}{path}",
            origin=f"https://{host}",
            ping_interval=None, close_timeout=2,
        ) as ws:
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=12)
                return msg
            except asyncio.TimeoutError:
                return None
    except Exception as exc:
        return f"ERR: {type(exc).__name__}: {exc}"


def step_ws_capture(ws_paths_found):
    banner("[5/5] CAPTURA DE FRAME DO WS (paths encontrados)")
    out = []
    for path in ws_paths_found:
        if path.startswith("/"):
            print(f"\n  tentando wss://ds.rainha777slots.com{path}")
            msg = asyncio.run(capture_ws("ds.rainha777slots.com", path))
            if isinstance(msg, str) and msg.startswith("ERR"):
                print(f"    {msg}")
                out.append({"path": path, "error": msg})
                continue
            if msg is None:
                out.append({"path": path, "timeout": True})
                continue
            if isinstance(msg, str):
                print(f"    text: {msg[:200]}")
                try:
                    obj = json.loads(msg)
                    inner = obj.get("msg")
                    if inner:
                        import base64
                        proto_bytes = base64.b64decode(inner)
                        summary = ws_inspector.summarise_frame(proto_bytes)
                        print(f"    summary: {summary}")
                        out.append({"path": path, "envelope": obj, "summary": summary})
                    else:
                        out.append({"path": path, "envelope": obj})
                except Exception:
                    out.append({"path": path, "text": msg[:300]})
            else:
                summary = ws_inspector.summarise_frame(msg)
                print(f"    bytes ({len(msg)}): {msg[:64].hex()}  summary={summary}")
                out.append({"path": path, "size": len(msg), "summary": summary})
    return out


def main():
    out = {}
    out["ws_path"] = step_ws_path()
    out["pa_and_m"] = step_pa_and_m()
    out["bundle_compare"] = step_compare_bundles()
    out["api_ports"] = step_api_ports()
    
    # Capturar WS com paths que retornaram 101
    successful = [p["path"] for p in out["ws_path"]["probes"] if p["status"] == 101]
    if successful:
        out["ws_capture"] = step_ws_capture(successful)
    else:
        # Tentar /notice e /notify mesmo assim
        out["ws_capture"] = step_ws_capture(["/notice", "/websocket"])
    
    Path("rainha_extra.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    print("\n  Salvo em rainha_extra.json")


if __name__ == "__main__":
    main()

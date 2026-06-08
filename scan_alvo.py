"""
Pipeline passivo unificado contra um alvo arbitrario.

Rodar com:
    python scan_alvo.py rainha777slots.com

Encadeia:
  [1] descoberta_full   — fontes passivas + DNS brute force + paths sensiveis
  [2] inspecao_distintos— reverse DNS + AWS ranges + headers profundos
  [3] analise_bundles   — baixa bundles JS, extrai endpoints/secrets
  [4] testes_endpoints  — testa endpoints sem auth + scan de auth admin
  [5] extra_recon       — paths /japi /admin /actuator + captcha + atividades
  [6] sessao_extra      — VHost + cache + WS handshake + S3
  [7] teste_modulos     — SSRF + CORS + cache_poison + ws_inspector

Salva tudo em scan_<alvo>.json e gera RELATORIO_<alvo>.html.
"""
from __future__ import annotations

import asyncio
import concurrent.futures as cf
import gzip
import hashlib
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from toolkit.discovery import (
    dns_records,
    origin_finder,
    subdomain_sources,
    waf_fingerprint,
    wayback,
    ws_inspector,
)
from toolkit.execution.checks import (
    cache_poison as cp_check,
    cors as cors_check,
    ssrf as ssrf_check,
    jwt_inspector,
)
from toolkit.analysis.classifiers import (
    cache_poison as cp_cls,
    cors as cors_cls,
    ssrf as ssrf_cls,
    secrets as secrets_cls,
)

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
HTTP_TIMEOUT = 20.0


def banner(t):
    print(f"\n{'=' * 70}\n  {t}\n{'=' * 70}")


def fetch(url, *, method="GET", headers=None, body=None, timeout=HTTP_TIMEOUT):
    h = {"User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "gzip"}
    if headers:
        h.update(headers)
    req = Request(url, method=method, data=body, headers=h)
    start = time.time()
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            if resp.headers.get("content-encoding") == "gzip":
                raw = gzip.decompress(raw)
            return resp.status, dict(resp.getheaders()), raw, int((time.time() - start) * 1000)
    except HTTPError as exc:
        try:
            raw = exc.read()
        except Exception:
            raw = b""
        return exc.code, dict(exc.headers or {}), raw, int((time.time() - start) * 1000)
    except Exception as exc:
        return None, {}, str(exc).encode(), 0


# ----------------------------------------------------------------------
# Resolutores e probe
# ----------------------------------------------------------------------

def resolve(name):
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)})
    except OSError:
        return []


DNS_PREFIXES = [
    "www", "m", "mb", "ds", "dt", "app", "api", "api2", "rest", "graphql",
    "ws", "wss", "websocket", "static", "cdn", "cdn1", "assets", "img",
    "media", "files", "upload", "download", "auth", "login", "sso",
    "oauth", "id", "account", "register", "signup",
    "admin", "adm", "manage", "manager", "panel", "painel", "console",
    "operator", "agent", "agente", "afiliado", "afiliados",
    "backoffice", "internal", "intranet",
    "dev", "develop", "test", "qa", "uat", "stage", "staging", "homolog",
    "hml", "preview", "demo", "beta", "alpha", "sandbox",
    "casino", "slot", "slots", "bet", "bets", "game", "games", "jogo",
    "jogos", "play", "promo", "bonus", "vip", "wallet", "carteira",
    "saque", "deposito", "pix", "pagamento", "payment", "pay", "checkout",
    "mobile", "wap", "android", "ios",
    "v1", "v2", "v3", "old", "new", "next", "legacy",
    "support", "suporte", "help", "kb", "faq",
    "monitor", "metrics", "grafana", "kibana", "prometheus",
    "br", "us", "lat",
]


SENSITIVE_PATHS = [
    "/.git/config", "/.git/HEAD", "/.env", "/.env.local",
    "/.env.production", "/config.json", "/config.js", "/composer.json",
    "/package.json", "/package-lock.json", "/Dockerfile",
    "/docker-compose.yml", "/.aws/credentials", "/.npmrc", "/.htaccess",
    "/web.config", "/server-status", "/server-info", "/phpinfo.php",
    "/info.php", "/health", "/healthz", "/healthcheck", "/status",
    "/metrics", "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/heapdump", "/swagger-ui.html", "/swagger",
    "/swagger.json", "/v2/api-docs", "/v3/api-docs", "/api-docs",
    "/openapi.json", "/robots.txt", "/sitemap.xml", "/manifest.json",
    "/security.txt", "/.well-known/security.txt", "/admin", "/admin/",
    "/admin/login", "/manage", "/manager", "/console",
    "/japi/", "/prod-api/", "/api", "/api/", "/api/v1", "/api/v2",
    "/internal", "/debug", "/error.log", "/access.log",
    "/backup", "/backup.zip", "/dump.sql", "/db.sql",
    "/.svn/entries", "/wp-admin/", "/wp-login.php", "/wp-config.php",
    "/.DS_Store",
]


COMMON_API_PATHS = [
    # /japi
    "/japi/user/captcha/image",
    "/japi/user/balance/querySimpleBalance",
    "/japi/user/game/getGameLabel",
    "/japi/user/game/getGameList",
    "/japi/user/getDama",
    "/japi/user/getExtraInfo",
    "/japi/user/vip/getAllDisplayVo",
    "/japi/user/api/signIn/customerSignConfig",
    "/japi/user/api/signIn/signRecord",
    "/japi/user/api/signIn/v2/signIn",
    "/japi/activity/redPacketRain/currentRedPacketRainActivityList",
    "/japi/activity/redPacketRain/redPacketRainActivityList",
    "/japi/activity/redPacketRain/getRedPacket",
    "/japi/activity/redPacketRain/getReward",
    "/japi/invite/api/finger/download?packageName=com.slots.big",
    "/japi/invite/boxConfig/boxInfo",
    "/japi/invite/boxConfig/boxReceive",
    "/japi/invite/boxConfig/boxReceiveRecord",
    "/japi/invite/userInvite/getInviteConfig",
    "/japi/invite/userInvite/getRewardRecordList",
    "/japi/system/admin",
    "/japi/system/log",
    "/japi/system/config",
    "/japi/user/info/1",
    "/japi/user/list",
    "/japi/admin",
    # /prod-api
    "/prod-api/player/sign-in",
    "/prod-api/pay-service/recharge",
    "/prod-api/payment/balance-less",
    "/prod-api/vip/info",
    "/prod-api/global-config/recharge",
    "/prod-api/admin/list",
]


def step_dns(apex):
    banner(f"[1/8] DNS BRUTE-FORCE — {apex}")
    candidates = [apex] + [f"{p}.{apex}" for p in DNS_PREFIXES]
    found = {}
    with cf.ThreadPoolExecutor(max_workers=30) as ex:
        for name, ips in zip(candidates, ex.map(resolve, candidates)):
            if ips:
                found[name] = ips
                print(f"  [OK] {name:<40s} -> {', '.join(ips)}")
    return found


def step_passive_sources(apex):
    banner(f"[2/8] FONTES PASSIVAS DE SUBDOMINIO — {apex}")
    agg = subdomain_sources.aggregate_subdomains(apex)
    print(f"  total unico: {len(agg.subdomains)}")
    for s in agg.sources:
        if s.succeeded:
            print(f"    {s.name:14s}: {len(s.subdomains):4d} achados")
        else:
            print(f"    {s.name:14s}: ERRO {s.error}")
    print(f"\n  primeiros 30:")
    for s in agg.subdomains[:30]:
        print(f"    {s}")
    return agg.to_dict()


def step_dns_records(apex):
    banner(f"[3/8] DNS RECORDS — {apex}")
    profile = dns_records.query_records(apex)
    print(f"  has_spf={profile.has_spf}  has_dmarc={profile.has_dmarc}  has_caa={profile.has_caa}")
    for rt, rs in profile.records.items():
        if rs.error:
            print(f"  {rt:6s}: erro ({rs.error})")
        elif rs.values:
            print(f"  {rt:6s}: {', '.join(rs.values[:3])}")
    return profile.to_dict()


def step_origin(apex, all_subs):
    banner(f"[4/8] ORIGIN-IP FINDER — {apex}")
    report = origin_finder.find_origin_candidates(apex, extra_subdomains=all_subs)
    print(f"  total candidatos: {len(report.candidates)}")
    print(f"  promissores (fora CDN): {len(report.promising)}")
    print(f"  atras de CDN: {len(report.behind_cdn)}")
    for c in report.promising[:10]:
        print(f"    PROMISSOR: {c.address:15s}  src={c.source}  host={c.related_host}")
    for c in report.behind_cdn[:8]:
        print(f"    cdn {c.cdn:10s}: {c.address:15s}  host={c.related_host}")
    return report.to_dict()


def step_probe_main(targets):
    banner("[5/8] PROBE HTTP + WAF FINGERPRINT — alvos principais")
    out = []
    for t in targets:
        url = f"https://{t}/"
        status, headers, body, ms = fetch(url, timeout=15)
        if status is None:
            print(f"  {t}: ERRO {body[:200]}")
            out.append({"target": t, "error": True})
            continue
        cookies = []
        sc = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
        if sc:
            for piece in sc.split(","):
                name = piece.split("=", 1)[0].strip()
                if name:
                    cookies.append(name)
        fp = waf_fingerprint.fingerprint(headers, cookies=cookies)
        # Headers de seguranca
        sec_headers_present = []
        for h in ("content-security-policy", "x-frame-options",
                  "strict-transport-security", "x-content-type-options",
                  "referrer-policy", "permissions-policy"):
            if h in {k.lower() for k in headers}:
                sec_headers_present.append(h)
        print(f"  {t}: status={status} bytes={len(body)} ms={ms} waf={fp.detected}")
        print(f"    server: {headers.get('Server') or headers.get('server')}")
        print(f"    via: {headers.get('Via') or headers.get('via')}")
        print(f"    headers seguranca: {sec_headers_present or ['NENHUM']}")
        out.append({
            "target": t, "url": url, "status": status, "size": len(body),
            "headers": headers, "set_cookie": cookies, "waf": fp.to_dict(),
            "security_headers_present": sec_headers_present,
            "body_preview": body[:300].decode("utf-8", errors="replace"),
        })
    return out


def step_sensitive_paths(target):
    banner(f"[6/8] PATHS SENSIVEIS EM {target}")

    def probe(path):
        url = f"https://{target}{path}"
        status, headers, body, _ = fetch(url, timeout=10)
        if status is None:
            return {"path": path, "error": True}
        ctype = (headers.get("Content-Type") or headers.get("content-type") or "").split(";")[0].strip()
        text = body[:200].decode("utf-8", errors="replace")
        # Marcar interessante apenas se conteudo distinto da SPA
        size = len(body)
        is_404_payload = "404 NOT_FOUND" in text or "code\":500" in text
        return {
            "path": path, "status": status, "size": size, "ctype": ctype,
            "body": text, "is_404_payload": is_404_payload,
        }

    results = []
    with cf.ThreadPoolExecutor(max_workers=15) as ex:
        for r in ex.map(probe, SENSITIVE_PATHS):
            results.append(r)

    # Identifica baseline (size mais comum)
    sizes = [r["size"] for r in results if r.get("size") and not r.get("error")]
    baseline_size = max(set(sizes), key=sizes.count) if sizes else 0
    print(f"  baseline size detectado: {baseline_size} bytes")
    distinct = [r for r in results
                if r.get("size") and r["size"] != baseline_size and not r.get("error")]
    print(f"  paths com conteudo distinto: {len(distinct)}/{len(results)}")
    for r in distinct[:30]:
        print(f"    {r['status']:>3} {r['size']:>6}b  {r['path']:<35s}  {r['ctype']:<25s}  {r['body'][:60]!r}")
    return {"baseline_size": baseline_size, "results": results, "distinct": distinct}


def step_api_endpoints(target):
    banner(f"[6.5/8] ENDPOINTS COMUNS DE API EM {target}")

    def probe(path):
        url = f"https://{target}{path}"
        status, headers, body, _ = fetch(url, timeout=10)
        if status is None:
            return {"path": path, "error": True}
        ctype = (headers.get("Content-Type") or headers.get("content-type") or "").split(";")[0].strip()
        text = body[:200].decode("utf-8", errors="replace")
        is_json = "application/json" in ctype
        is_404_payload = "404 NOT_FOUND" in text or '"code":500' in text and "404" in text
        is_401 = '"code":401' in text or '"token is empty"' in text
        is_real_data = is_json and not is_404_payload and not is_401 and len(body) > 60
        return {
            "path": path, "status": status, "size": len(body), "ctype": ctype,
            "body": text, "is_real_data": is_real_data, "is_401": is_401,
        }

    results = []
    with cf.ThreadPoolExecutor(max_workers=15) as ex:
        for r in ex.map(probe, COMMON_API_PATHS):
            results.append(r)

    real = [r for r in results if r.get("is_real_data")]
    auth_required = [r for r in results if r.get("is_401")]
    print(f"\n  endpoints com dados sem auth ({len(real)}):")
    for r in real:
        print(f"    {r['status']:>3} {r['size']:>5}b  {r['path']}")
        print(f"        body: {r['body'][:200]}")
    print(f"\n  endpoints que pedem token ({len(auth_required)}):")
    for r in auth_required[:30]:
        print(f"    {r['path']}")
    return {"open_data": real, "auth_required": auth_required, "all": results}


def step_bundles(target):
    banner(f"[7/8] DOWNLOAD E ANALISE DE BUNDLES JS — {target}")
    bundle_dir = ROOT / "bundles"
    bundle_dir.mkdir(exist_ok=True)
    # 1) HTML
    status, _, body, _ = fetch(f"https://{target}/", timeout=15)
    if status != 200:
        print(f"  HTML nao retornou 200, status={status}")
        return {"error": "no html"}
    html = body.decode("utf-8", errors="replace")

    # 2) URLs de assets
    asset_urls = set()
    for m in re.findall(r'(?:src|href)\s*=\s*["\']([^"\']+\.(?:js|css)[^"\']*)["\']', html, re.I):
        if m.startswith("//"):
            url = "https:" + m
        elif m.startswith("http"):
            url = m
        elif m.startswith("/"):
            url = f"https://{target}{m}"
        else:
            url = f"https://{target}/{m}"
        asset_urls.add(url)

    print(f"  {len(asset_urls)} bundles referenciados")

    bundle_results = []
    js_text_chunks = []
    for url in sorted(asset_urls):
        status, headers, body, _ = fetch(url, timeout=45)
        if status != 200 or not body:
            bundle_results.append({"url": url, "status": status, "size": 0})
            continue
        text = body.decode("utf-8", errors="replace")
        sha = hashlib.sha256(body).hexdigest()[:16]
        fname = url.rsplit("/", 1)[-1].split("?")[0]
        local = bundle_dir / f"{target}_{fname}"
        local.write_bytes(body)
        ctype = (headers.get("content-type") or headers.get("Content-Type") or "").split(";")[0]
        print(f"  [{status}] {url} ({len(body)} bytes, sha={sha})")
        bundle_results.append({
            "url": url, "status": status, "size": len(body),
            "sha256_16": sha, "ctype": ctype, "saved_as": local.name,
        })
        if "javascript" in ctype or url.endswith(".js"):
            js_text_chunks.append(text)

    merged = "\n".join(js_text_chunks)
    print(f"\n  total {len(merged):,} chars de JS unificado")

    # 3) Endpoints e secrets
    api_paths = sorted(set(re.findall(
        r'["\'](/(?:prod-api|japi|api|admin|manage)/[a-zA-Z0-9_\-/\.\?=&]{1,200})["\']',
        merged,
    )))[:200]
    websockets = sorted(set(re.findall(
        r"wss?://[a-zA-Z0-9\-\.]+(?::\d+)?[a-zA-Z0-9_\-/\.]*",
        merged,
    )))[:30]
    full_urls = sorted(set(re.findall(
        r'["\']https?://[a-zA-Z0-9\-\.]+(?::\d+)?[a-zA-Z0-9_\-/\.\?=&]{0,200}["\']',
        merged,
    )))[:100]
    domains = sorted({
        u.split("//", 1)[1].split("/", 1)[0].split(":", 1)[0].split("\"")[0].split("'")[0].lower()
        for u in full_urls
    })

    aws_keys = sorted(set(re.findall(r"\bAKIA[0-9A-Z]{16}\b", merged)))
    google_keys = sorted(set(re.findall(r"\bAIza[0-9A-Za-z\-_]{35}\b", merged)))
    pem_keys = sorted(set(re.findall(r"-----BEGIN [A-Z ]+PRIVATE KEY-----", merged)))
    eth_pks = sorted(set(re.findall(r"\b0x[a-fA-F0-9]{64}\b", merged)))
    versions = sorted(set(re.findall(
        r'\b(?:version|VERSION|appVersion)\s*[:=]\s*["\']([^"\']+)["\']', merged,
    )))

    config_baseurl = sorted(set(re.findall(
        r'\b(?:baseURL|BASE_URL|api_base|apiBase)\s*[:=]\s*["\']([^"\']+)["\']', merged,
    )))

    # ws_inspector catalog se for grande
    catalog = ws_inspector.extract_message_catalog(merged) if len(merged) > 100_000 else None

    # Toolkit secrets analyzer
    try:
        sec_report = secrets_cls.analyze_bundle_hits({"merged.js": merged})
        sec_findings = [f.__dict__ if hasattr(f, "__dict__") else str(f) for f in sec_report.findings]
    except Exception as exc:
        sec_findings = [{"error": str(exc)}]

    print(f"\n  api endpoints: {len(api_paths)}")
    print(f"  websockets:    {len(websockets)}")
    print(f"  dominios:      {len(domains)}")
    print(f"  AWS keys:      {len(aws_keys)}")
    print(f"  Google keys:   {len(google_keys)}")
    print(f"  PEM keys:      {len(pem_keys)}")
    print(f"  Eth PKs:       {len(eth_pks)}")
    print(f"  versoes:       {versions}")
    print(f"  baseURL/api_base: {config_baseurl}")
    if catalog:
        print(f"  proto messages (ws_inspector): {len(catalog.messages)}")
        for k, v in catalog.by_suffix.items():
            print(f"    {k}: {len(v)}")

    if api_paths[:30]:
        print("\n  primeiros 20 endpoints:")
        for p in api_paths[:20]:
            print(f"    {p}")
    if domains:
        print("\n  dominios externos referenciados:")
        for d in domains[:30]:
            print(f"    {d}")

    return {
        "bundles": bundle_results,
        "merged_size": len(merged),
        "api_endpoints": api_paths,
        "websockets": websockets,
        "external_urls": full_urls[:50],
        "external_domains": domains,
        "aws_keys": aws_keys,
        "google_keys": google_keys,
        "pem_keys": pem_keys,
        "eth_private_keys": eth_pks,
        "versions": versions,
        "config_baseurl": config_baseurl,
        "proto_catalog": (
            {"total": len(catalog.messages), "first_30": catalog.messages[:30],
             "by_suffix": {k: len(v) for k, v in catalog.by_suffix.items()}}
            if catalog else None
        ),
        "secrets_classifier": sec_findings,
    }


def step_security_modules(target):
    banner(f"[8/8] MODULOS NOVOS DO TOOLKIT — {target}")

    def cors_transport(url, *, method="GET", headers=None):
        s, h, b, _ = fetch(url, method=method, headers=headers or {}, timeout=10)
        return type("R", (), {"status": s, "headers": h, "body": b})()

    def cache_transport(url, headers=None):
        s, h, b, _ = fetch(url, headers=headers or {}, timeout=10)
        return type("R", (), {"status": s, "headers": h, "body": b})()

    def ssrf_transport(url):
        s, h, b, ms = fetch(url, timeout=10)
        return type("R", (), {"status": s, "body": b, "elapsed_ms": ms})()

    out = {}

    # --- CORS ---
    print("\n  CORS check em / e em endpoints publicos...")
    cors_results = {}
    test_urls = [f"https://{target}/", f"https://{target}/manifest.json"]
    for url in test_urls:
        try:
            r = cors_check.check_cors(url, transport=cors_transport)
            cls = cors_cls.analyze_cors(r)
            cors_results[url] = {
                "vulnerable": cls.is_vulnerable,
                "findings": [f.__dict__ for f in cls.findings],
                "first_acao": r.probes[0].acao if r.probes else None,
            }
            print(f"    {url}: vulnerable={cls.is_vulnerable} first_acao={r.probes[0].acao if r.probes else None}")
            for f in cls.findings:
                print(f"      [{f.severity}] {f.method} from {f.origin}: {f.reason[:80]}")
        except Exception as exc:
            cors_results[url] = {"error": str(exc)}
            print(f"    {url}: erro {exc}")
    out["cors"] = cors_results

    # --- Cache poison ---
    print("\n  cache-poison check em /...")
    try:
        r = cp_check.check_cache_poison(f"https://{target}/", transport=cache_transport)
        cls = cp_cls.analyze_cache_poison(r)
        out["cache_poison"] = {
            "vulnerable": cls.is_vulnerable,
            "findings": [f.__dict__ for f in cls.findings],
            "baseline_size": r.baseline_size,
        }
        print(f"    vulnerable={cls.is_vulnerable} findings={len(cls.findings)}")
        for f in cls.findings:
            print(f"    [{f.severity}] {f.header}={f.value}: {f.reason}")
    except Exception as exc:
        out["cache_poison"] = {"error": str(exc)}

    # --- WebSocket inspector ---
    print("\n  WS handshake low-level em /websocket6...")

    async def ws_probe(host):
        try:
            import websockets
            async with websockets.connect(
                f"wss://{host}/websocket6", origin=f"https://{host}",
                ping_interval=None, close_timeout=2,
            ) as ws:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=12)
                    return msg
                except asyncio.TimeoutError:
                    return None
        except Exception as exc:
            return f"ERR: {type(exc).__name__}: {exc}"

    msg = asyncio.run(ws_probe(target))
    if isinstance(msg, str) and msg.startswith("ERR"):
        print(f"    {msg}")
        out["ws"] = {"error": msg}
    elif msg is None:
        print("    sem frame em 12s")
        out["ws"] = {"timeout": True}
    elif isinstance(msg, str):
        print(f"    text frame: {msg[:200]}")
        try:
            obj = json.loads(msg)
            inner_b64 = obj.get("msg")
            if inner_b64:
                import base64
                inner = base64.b64decode(inner_b64)
                summary = ws_inspector.summarise_frame(inner)
                print(f"    inner protobuf summary: {summary}")
                out["ws"] = {"text_envelope": obj, "inner_summary": summary}
            else:
                out["ws"] = {"text_envelope": obj}
        except Exception as exc:
            out["ws"] = {"text": msg[:300], "parse_error": str(exc)}
    else:
        # bytes
        summary = ws_inspector.summarise_frame(msg)
        print(f"    bytes frame ({len(msg)}): summary={summary}")
        out["ws"] = {"size": len(msg), "summary": summary}

    return out


def step_wayback(apex):
    banner(f"[wayback] {apex}")
    out = wayback.collect(apex, timeout=20)
    print(f"  total URLs: {len(out.urls)}  sources={out.sources}  errors={out.errors}")
    params = wayback.extract_parameters(out.urls)
    print(f"  endpoints com params: {len(params)}")
    for ep, ps in list(params.items())[:10]:
        print(f"    {ep} -> {sorted(ps)}")
    return {
        "total": len(out.urls), "sources": out.sources, "errors": out.errors,
        "first_50": out.urls[:50],
        "endpoints_with_params": {k: sorted(v) for k, v in list(params.items())[:30]},
    }


def main():
    if len(sys.argv) < 2:
        print("Uso: python scan_alvo.py <apex>")
        sys.exit(1)
    apex = sys.argv[1].strip().lower()
    print(f"\n  ALVO: {apex}\n")

    out = {
        "apex": apex,
        "timestamp": datetime.now().isoformat(),
    }

    out["dns_bruteforce"] = step_dns(apex)
    out["passive_sources"] = step_passive_sources(apex)
    out["dns_records"] = step_dns_records(apex)

    all_subs = sorted(set(
        list(out["dns_bruteforce"].keys()) +
        out["passive_sources"].get("subdomains", [])
    ))
    out["all_subdomains"] = all_subs

    out["origin"] = step_origin(apex, all_subs)

    # Selecionar alvos principais para probe — preferindo ones que respondem HTTP
    targets = []
    for s in all_subs:
        if s != apex:
            targets.append(s)
    targets = targets[:5]  # cap em 5
    if not targets:
        targets = [apex]
    print(f"\n  alvos principais para probe: {targets}")
    main_probes = step_probe_main(targets)
    out["main_probes"] = main_probes

    # Sensitive paths e endpoints API: usar primeiro alvo que respondeu
    primary = None
    for p in main_probes:
        if p.get("status") and p.get("status") < 500:
            primary = p["target"]
            break
    if primary is None:
        primary = targets[0] if targets else apex
    print(f"\n  alvo principal escolhido para deep scan: {primary}")
    out["primary_host"] = primary
    out["sensitive_paths"] = step_sensitive_paths(primary)
    out["api_endpoints"] = step_api_endpoints(primary)
    out["sensitive_paths"] = step_sensitive_paths(primary)
    out["api_endpoints"] = step_api_endpoints(primary)

    # Bundles
    try:
        out["bundles"] = step_bundles(primary)
    except Exception as exc:
        out["bundles"] = {"error": str(exc)}
        print(f"  ERRO no bundle analysis: {exc}")

    # Modulos novos
    try:
        out["security_modules"] = step_security_modules(primary)
    except Exception as exc:
        out["security_modules"] = {"error": str(exc)}
        print(f"  ERRO em security modules: {exc}")

    # Wayback (rapido)
    try:
        out["wayback"] = step_wayback(apex)
    except Exception as exc:
        out["wayback"] = {"error": str(exc)}

    # Salvar
    out_path = ROOT / f"scan_{apex.replace('.', '_')}.json"
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    print(f"\n  Resultado completo salvo em: {out_path}")

    # Resumo
    banner("RESUMO RAPIDO")
    print(f"  alvo: {apex}")
    print(f"  subdominios resolvidos: {len(out['dns_bruteforce'])}")
    print(f"  candidatos a IP de origem fora-CDN: {len(out['origin'].get('promising', []))}")
    print(f"  endpoints abertos sem auth: {len(out['api_endpoints'].get('open_data', []))}")
    print(f"  endpoints que pedem token: {len(out['api_endpoints'].get('auth_required', []))}")
    sec = out.get("security_modules", {})
    cors_vuln = sum(1 for v in (sec.get("cors") or {}).values() if isinstance(v, dict) and v.get("vulnerable"))
    print(f"  endpoints com CORS aberto: {cors_vuln}")
    print(f"  cache poisoning vulneravel: {sec.get('cache_poison', {}).get('vulnerable', '?')}")
    if isinstance(out.get("bundles"), dict) and out["bundles"].get("api_endpoints"):
        print(f"  endpoints extraidos do bundle JS: {len(out['bundles']['api_endpoints'])}")


if __name__ == "__main__":
    main()

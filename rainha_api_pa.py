"""
Recon profundo de api.rainha777slots.com (backend direto, sem CloudFront)
e pa.rainha777slots.com (painel de agentes).

Insights desta investigacao podem ser aplicados no amizade777 e em
qualquer outro tenant da mesma stack white-label.
"""
from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import re
import socket
import sys
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"


def fetch(url, *, method="GET", headers=None, body=None, timeout=15.0):
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


def banner(t):
    print(f"\n{'=' * 70}\n  {t}\n{'=' * 70}")


# ----------------------------------------------------------------------
# 1. Mapeamento profundo do api.rainha777slots.com:80
# ----------------------------------------------------------------------

def step_api_direct():
    banner("[1/3] api.rainha777slots.com:80 (BACKEND DIRETO, SEM CLOUDFRONT)")

    # Pega o /robots.txt e qualquer header /header diferente
    print("\n  === HEADERS COMPLETOS DA HOME ===")
    s, h, b, ms = fetch("http://api.rainha777slots.com/")
    print(f"  status={s} bytes={len(b)} ms={ms}")
    for k, v in h.items():
        print(f"    {k}: {v[:120]}")

    print("\n  === CRUZANDO ENDPOINTS /japi/ ENTRE BACKEND DIRETO E CLOUDFRONT ===")
    # Lista dos 23 endpoints reais que ja descobrimos no amizade777
    endpoints = [
        "/japi/user/captcha/image",
        "/japi/user/balance/querySimpleBalance",
        "/japi/user/getDama",
        "/japi/user/getExtraInfo",
        "/japi/user/vip/getAllDisplayVo",
        "/japi/user/api/signIn/customerSignConfig",
        "/japi/user/api/signIn/signRecord",
        "/japi/user/api/signIn/v2/signIn",
        "/japi/user/info/1",
        "/japi/user/list",
        "/japi/user/all",
        "/japi/system/admin",
        "/japi/system/log",
        "/japi/system/config",
        "/japi/system/health",
        "/japi/activity/redPacketRain/redPacketRainActivityList",
        "/japi/activity/redPacketRain/currentRedPacketRainActivityList",
        "/japi/activity/redPacketRain/getRedPacket",
        "/japi/invite/api/finger/download?packageName=com.slots.big",
        "/japi/invite/boxConfig/boxInfo",
        "/japi/invite/userInvite/getInviteConfig",
        "/japi/admin",
        "/japi/admin/list",
        "/japi/operator",
        "/japi/operator/list",
        # paths de agente/operador novos
        "/japi/agent",
        "/japi/agent/list",
        "/japi/agent/login",
        "/japi/agent/info",
        # spring actuator
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        "/actuator/heapdump",
        "/actuator/mappings",
        "/japi/actuator/health",
        # debug
        "/debug",
        "/error",
        "/health",
        "/info",
    ]
    out = []
    for ep in endpoints:
        url = f"http://api.rainha777slots.com{ep}"
        s, h, b, ms = fetch(url, timeout=8)
        if s is None:
            continue
        ctype = (h.get("Content-Type") or h.get("content-type") or "").split(";")[0].strip()
        text = b[:200].decode("utf-8", errors="replace").replace("\n", " ")
        is_404 = "404 NOT_FOUND" in text
        is_real = ctype == "application/json" and not is_404 and len(b) > 60
        is_401 = '"code":401' in text
        is_500_real = s == 500 and not is_404
        marker = ""
        if is_real:
            marker = "  <-- DADOS!"
        elif is_500_real:
            marker = "  <-- ERRO INTERNO"
        elif is_401:
            marker = "  pede token"
        if (is_real or is_500_real or s != 200) and not is_404:
            print(f"  {s:>3} {len(b):>5}b  {ep:<50s}  {ctype:<25s}  {text[:80]}{marker}")
        out.append({"path": ep, "status": s, "size": len(b), "ctype": ctype,
                    "body": text, "is_real": is_real, "is_401": is_401})

    # Tentar POST no /japi/player/sign-in pra ver se existe
    print("\n  === POST /japi/player/sign-in com payload simples ===")
    payload = json.dumps({
        "appChannel": "pc", "appPackageName": "com.slots.big",
        "deviceId": "test", "deviceModel": "WEB", "deviceVersion": "WEB",
        "appVersion": "1.0.0", "phone": "21998498419", "password": "wrong",
    }).encode()
    for ep in ("/japi/player/sign-in", "/prod-api/player/sign-in",
               "/japi/user/api/signIn/v2/signIn"):
        url = f"http://api.rainha777slots.com{ep}"
        s, h, b, ms = fetch(url, method="POST", body=payload,
                             headers={"Content-Type": "application/json"})
        if s:
            text = b[:300].decode("utf-8", errors="replace").replace("\n", " ")
            print(f"  POST {ep}: {s} {len(b)}b  {text[:200]}")

    return out


# ----------------------------------------------------------------------
# 2. Bundle do pa.rainha777slots.com (painel de agentes)
# ----------------------------------------------------------------------

def step_pa_bundle():
    banner("[2/3] BUNDLE DO pa.rainha777slots.com (PAINEL DE AGENTES)")
    bundles_dir = ROOT / "bundles"
    bundles_dir.mkdir(exist_ok=True)
    s, h, b, _ = fetch("https://pa.rainha777slots.com/")
    if s != 200:
        print(f"  HTML nao retornou 200, status={s}")
        return {"error": "no html"}
    html = b.decode("utf-8", errors="replace")
    print(f"  HTML home: {len(html)} chars")

    # Extrair urls de bundles
    asset_urls = set()
    for m in re.findall(r'(?:src|href)\s*=\s*["\']([^"\']+\.(?:js|css)[^"\']*)["\']', html, re.I):
        if m.startswith("//"):
            url = "https:" + m
        elif m.startswith("http"):
            url = m
        elif m.startswith("/"):
            url = f"https://pa.rainha777slots.com{m}"
        else:
            url = f"https://pa.rainha777slots.com/{m}"
        asset_urls.add(url)

    print(f"  bundles: {len(asset_urls)}")

    # Baixar e juntar
    js_chunks = []
    bundles_info = []
    for url in sorted(asset_urls):
        s, _, b, _ = fetch(url, timeout=45)
        if s != 200 or not b:
            continue
        text = b.decode("utf-8", errors="replace")
        sha = hashlib.sha256(b).hexdigest()[:16]
        fname = url.rsplit("/", 1)[-1].split("?")[0]
        local = bundles_dir / f"pa.rainha777slots.com_{fname}"
        local.write_bytes(b)
        bundles_info.append({"url": url, "size": len(b), "sha": sha, "saved": local.name})
        print(f"  [{s}] {url} ({len(b)} bytes, sha={sha})")
        if url.endswith(".js"):
            js_chunks.append(text)

    merged = "\n".join(js_chunks)
    print(f"\n  total {len(merged):,} chars de JS unificado")

    # Endpoints
    api_paths = sorted(set(re.findall(
        r'["\'](/(?:prod-api|japi|api|admin|manage|operator|agent|backoffice)/[a-zA-Z0-9_\-/\.\?=&]{1,200})["\']',
        merged,
    )))
    print(f"  api endpoints achados: {len(api_paths)}")
    for p in api_paths[:60]:
        print(f"    {p}")

    # Procurar palavras-chave especificas de painel de agente
    keywords = ["agent", "agente", "operator", "operador", "afiliado", "affiliate",
                "commission", "comissao", "withdraw", "saque", "deposit",
                "deposito", "user", "player", "balance", "config", "manage",
                "backoffice", "admin", "login"]
    keyword_hits = {}
    for kw in keywords:
        # context com pequeno regex
        matches = re.findall(rf'\b{kw}[a-zA-Z]*\b', merged, re.IGNORECASE)
        keyword_hits[kw] = len(set(matches))
    print(f"\n  keywords no bundle:")
    for kw, n in keyword_hits.items():
        if n > 0:
            print(f"    {kw}: {n} ocorrencias unicas")

    # Procurar configuracao de baseURL
    base_urls = sorted(set(re.findall(
        r'\b(?:baseURL|BASE_URL|api_base|apiBase|VITE_[A-Z_]+)\s*[:=]\s*["\']([^"\']+)["\']',
        merged,
    )))
    print(f"\n  baseURLs / VITE_*: {base_urls}")

    # Procurar urls externas
    external_urls = sorted(set(re.findall(
        r"https?://[a-zA-Z0-9\-\.]+(?::\d+)?[a-zA-Z0-9_\-/\.\?=&]{0,150}",
        merged,
    )))[:50]
    domains = sorted({
        u.split("//", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
        for u in external_urls
    })
    print(f"\n  dominios externos: {domains}")

    return {
        "html_size": len(html),
        "bundles": bundles_info,
        "merged_size": len(merged),
        "api_endpoints": api_paths,
        "keyword_hits": keyword_hits,
        "base_urls": base_urls,
        "external_domains": domains,
        "external_urls_sample": external_urls[:30],
    }


# ----------------------------------------------------------------------
# 3. Comparar bundle do pa. com m./ds. pra ver se eh nova app
# ----------------------------------------------------------------------

def step_pa_endpoints():
    banner("[3/3] TESTE DE ENDPOINTS DESCOBERTOS NO pa.")
    bundles_dir = ROOT / "bundles"
    pa_files = [f for f in bundles_dir.iterdir() if f.name.startswith("pa.rainha")]
    if not pa_files:
        return {"error": "no pa bundles"}
    text = "\n".join(f.read_text(encoding="utf-8", errors="replace") for f in pa_files)
    print(f"  total bundle pa: {len(text):,} chars")

    # Procurar endpoints
    api_paths = sorted(set(re.findall(
        r'["\'](/(?:prod-api|japi|api|admin|manage|operator|agent|backoffice|aapi)/[a-zA-Z0-9_\-/\.\?=&]{1,200})["\']',
        text,
    )))[:60]
    if not api_paths:
        # Caso comum: endpoints sao concatenados a partir de variaveis. Vamos buscar
        # apenas paths estaticos comuns
        api_paths = sorted(set(re.findall(
            r"['\"]\s*(/[a-zA-Z][a-zA-Z0-9/_\-]{4,80})\s*['\"]", text,
        )))[:80]

    print(f"  endpoints unicos: {len(api_paths)}")
    out = []
    for ep in api_paths[:30]:
        # Testar via pa. host primeiro
        url = f"https://pa.rainha777slots.com{ep}"
        s, h, b, _ = fetch(url, timeout=8)
        if s is None:
            continue
        ctype = (h.get("Content-Type") or "").split(";")[0]
        text2 = b[:120].decode("utf-8", errors="replace").replace("\n", " ")
        is_json = "application/json" in ctype
        is_404 = "404 NOT_FOUND" in text2
        is_html = "<!DOCTYPE" in text2
        # only report json or non-html responses
        if (is_json and not is_404) or (s != 200) or not is_html:
            print(f"  {s:>3} {len(b):>5}b  {ep:<40s}  ctype={ctype:<25s}  {text2[:100]}")
            out.append({"endpoint": ep, "status": s, "ctype": ctype, "body": text2})

    return {"endpoints_found": api_paths, "probes": out}


def main():
    out = {}
    out["api_direct"] = step_api_direct()
    out["pa_bundle"] = step_pa_bundle()
    out["pa_endpoints"] = step_pa_endpoints()
    Path("rainha_api_pa.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    print("\n  Salvo em rainha_api_pa.json")


if __name__ == "__main__":
    main()

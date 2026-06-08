"""
Extra recon:
  1. Descoberta do dominio megaslott.com (apex novo achado no APK URL)
  2. Brute-force de paths sob /japi/ (admin, system, manager, debug, etc.)
  3. Inspecao detalhada das atividades redPacketRain (timing/regras)
  4. Probe do captcha sem sessao (verificar se permite bypass)
"""
from __future__ import annotations

import concurrent.futures as cf
import gzip
import json
import socket
import sys
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"


def fetch(url: str, *, method: str = "GET", body: bytes | None = None,
          timeout: float = 12.0):
    req = Request(url, method=method, data=body,
                  headers={"User-Agent": UA, "Accept": "application/json,*/*",
                           "Accept-Encoding": "gzip"})
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


def banner(t: str) -> None:
    print(f"\n{'=' * 70}\n  {t}\n{'=' * 70}")


# ----------------------------------------------------------------------
# 1. megaslott.com
# ----------------------------------------------------------------------

def step_megaslott() -> dict:
    banner("[1/4] DESCOBERTA DE megaslott.com (achado no /japi/invite/api/finger/download)")
    out: dict = {"apex": "megaslott.com"}

    prefixes = ["www", "sx", "ds", "m", "api", "app", "admin", "panel",
                "mobile", "static", "cdn", "download", "dl", "agent",
                "agente", "operator", "operador", "dev", "test", "staging",
                "uat", "qa", "stage"]
    found = {}
    for p in prefixes:
        host = f"{p}.megaslott.com"
        try:
            ips = sorted({i[4][0] for i in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
            found[host] = ips
            print(f"    [DNS] {host} -> {', '.join(ips)}")
        except OSError:
            continue
    out["dns"] = found

    # apex
    try:
        ips = sorted({i[4][0] for i in socket.getaddrinfo("megaslott.com", None, type=socket.SOCK_STREAM)})
        found["megaslott.com"] = ips
        print(f"    [DNS] megaslott.com -> {', '.join(ips)}")
    except OSError:
        print("    apex nao resolve")

    # Probe HTTP
    print()
    for host, ips in found.items():
        url = f"https://{host}/"
        status, headers, body = fetch(url)
        if status:
            ctype = headers.get("Content-Type") or headers.get("content-type") or ""
            print(f"    [{status}] {url}  bytes={len(body)}  ctype={ctype.split(';')[0]}")
            via = headers.get("Via") or headers.get("via")
            if via:
                print(f"        via: {via}")
        else:
            print(f"    [---] {url}  erro")

    # APK direto
    apk_url = "https://sx.megaslott.com/download/Amizade777.apk"
    print(f"\n    HEAD em {apk_url}")
    status, headers, body = fetch(apk_url, method="HEAD", timeout=20)
    if status:
        print(f"      status={status}  size={headers.get('Content-Length') or '?'}")
        print(f"      content-type: {headers.get('Content-Type') or '?'}")
        print(f"      last-modified: {headers.get('Last-Modified') or '?'}")
        print(f"      server: {headers.get('Server') or '?'}")
        out["apk_head"] = {
            "status": status,
            "content_length": headers.get("Content-Length"),
            "content_type": headers.get("Content-Type"),
            "last_modified": headers.get("Last-Modified"),
            "server": headers.get("Server"),
        }
    return out


# ----------------------------------------------------------------------
# 2. brute force em /japi/
# ----------------------------------------------------------------------

JAPI_PATHS = [
    # admin variantes
    "/japi/admin", "/japi/admin/", "/japi/admin/list",
    "/japi/admin/user", "/japi/admin/user/list",
    "/japi/admin/player", "/japi/admin/player/list",
    "/japi/admin/recharge", "/japi/admin/withdraw",
    "/japi/admin/finance", "/japi/admin/config",
    "/japi/admin/log", "/japi/admin/logs",
    "/japi/admin/audit",
    # system / management
    "/japi/system", "/japi/system/admin", "/japi/system/info",
    "/japi/system/status", "/japi/system/health",
    "/japi/system/log", "/japi/system/config",
    "/japi/manage", "/japi/manage/user", "/japi/manage/player",
    "/japi/manager", "/japi/manager/list",
    "/japi/operator", "/japi/operator/list",
    "/japi/agent", "/japi/agent/list",
    "/japi/staff", "/japi/internal",
    "/japi/backoffice", "/japi/back",
    # debug / diagnostic
    "/japi/debug", "/japi/dev", "/japi/test", "/japi/info",
    "/japi/version", "/japi/health", "/japi/healthz",
    "/japi/actuator", "/japi/actuator/health", "/japi/actuator/env",
    "/japi/actuator/heapdump", "/japi/actuator/mappings",
    "/japi/actuator/info", "/japi/actuator/configprops",
    "/japi/actuator/beans", "/japi/actuator/threaddump",
    "/japi/actuator/loggers",
    # docs/swagger
    "/japi/swagger-ui.html", "/japi/swagger", "/japi/swagger.json",
    "/japi/v2/api-docs", "/japi/v3/api-docs", "/japi/api-docs",
    "/japi/openapi.json", "/japi/openapi", "/japi/docs",
    # finance / payment
    "/japi/finance", "/japi/finance/list",
    "/japi/payment", "/japi/payment/list",
    "/japi/recharge", "/japi/recharge/list",
    "/japi/withdraw", "/japi/withdraw/list",
    "/japi/order", "/japi/order/list",
    "/japi/wallet", "/japi/wallet/list",
    "/japi/transaction", "/japi/transaction/list",
    # user
    "/japi/user", "/japi/user/list",
    "/japi/user/all", "/japi/user/search",
    "/japi/user/info", "/japi/user/info/1",
    "/japi/user/profile", "/japi/user/profile/1",
    "/japi/users", "/japi/users/list",
    "/japi/player", "/japi/player/1", "/japi/player/list",
    "/japi/account", "/japi/account/list",
    # game
    "/japi/game", "/japi/game/list",
    "/japi/games", "/japi/bet", "/japi/bet/list",
    # invite (extras)
    "/japi/invite", "/japi/invite/list",
    "/japi/invite/admin",
    # outros
    "/japi/.env", "/japi/config", "/japi/config.json",
    "/japi/jdbc.properties", "/japi/application.yml",
    "/japi/application.properties", "/japi/.git/HEAD",
]


def step_japi_brute(target: str = "ds.amizade777.com") -> list[dict]:
    banner(f"[2/4] BRUTE FORCE EM /japi/ EM {target}")

    def probe(path: str):
        url = f"https://{target}{path}"
        status, headers, body = fetch(url, timeout=10)
        if status is None:
            return {"path": path, "error": True}
        ctype = (headers.get("Content-Type") or headers.get("content-type") or "").split(";")[0].strip()
        text = body.decode("utf-8", errors="replace")[:200]
        # interesante = !=404 NOT_FOUND
        is_404_payload = "404 NOT_FOUND" in text
        is_500 = '"code":500' in text
        is_401 = '"code":401' in text
        # Ignora respostas padrao "404 NOT_FOUND"
        interesting = not is_404_payload and not (is_500 and is_404_payload)
        return {
            "path": path,
            "status": status,
            "size": len(body),
            "ctype": ctype,
            "body": text,
            "interesting": interesting and status != 404,
            "is_401": is_401,
            "is_500_404": is_404_payload,
        }

    results = []
    with cf.ThreadPoolExecutor(max_workers=10) as ex:
        for r in ex.map(probe, JAPI_PATHS):
            results.append(r)
    
    # Mostra apenas os interessantes (ignorando os 401 padrao e os 404)
    interesting = [r for r in results if r.get("interesting") and not r.get("is_401")]
    print(f"\n  {len(interesting)}/{len(results)} paths nao retornaram '404 NOT_FOUND' nem 401 padrao:")
    for r in interesting:
        print(f"    {r['status']:>3} {r.get('size'):>5}b  {r['path']:<50s}  {r.get('ctype')}")
        print(f"        body: {r.get('body')[:200]}")
    
    print(f"\n  PATHS QUE SO PEDIRAM TOKEN ({sum(1 for r in results if r.get('is_401'))}):")
    for r in results:
        if r.get("is_401"):
            print(f"    {r['path']}")
    
    return results


# ----------------------------------------------------------------------
# 3. captcha sem sessao
# ----------------------------------------------------------------------

def step_captcha_bypass() -> dict:
    banner("[3/4] CAPTCHA: bypass de sessao")
    print("  Repete o GET 5 vezes sem cookies pra ver se cada call retorna captcha distinto")
    out: list = []
    for i in range(5):
        status, headers, body = fetch("https://ds.amizade777.com/japi/user/captcha/image")
        if status == 200:
            sha = body[:200].hex()[:32]
            out.append({"call": i, "size": len(body), "first_bytes_hex": sha,
                        "set_cookie": headers.get("Set-Cookie")})
            print(f"    call {i}: status={status} size={len(body)} first_bytes={sha[:16]}... cookie={headers.get('Set-Cookie')}")
        else:
            out.append({"call": i, "error": status})
        time.sleep(0.5)
    return {"calls": out}


# ----------------------------------------------------------------------
# 4. Detalhe das atividades RedPacket
# ----------------------------------------------------------------------

def step_redpacket() -> dict:
    banner("[4/4] DETALHE DAS ATIVIDADES redPacketRain")
    out = {}
    for ep in ("currentRedPacketRainActivityList", "redPacketRainActivityList"):
        url = f"https://ds.amizade777.com/japi/activity/redPacketRain/{ep}"
        status, headers, body = fetch(url)
        if status == 200:
            try:
                obj = json.loads(body.decode("utf-8"))
            except Exception:
                obj = {"_raw": body.decode("utf-8", errors="replace")}
            print(f"\n  --- {ep} ---")
            print(json.dumps(obj, indent=2, ensure_ascii=False)[:2000])
            out[ep] = obj
    return out


def main() -> None:
    out = {
        "megaslott": step_megaslott(),
        "japi_brute": step_japi_brute(),
        "captcha": step_captcha_bypass(),
        "redpacket": step_redpacket(),
    }
    Path("extra_recon.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    print("\n  Salvo em extra_recon.json")


if __name__ == "__main__":
    main()

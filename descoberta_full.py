"""
Descoberta passiva agressiva — versao com retry, UA realista e wordlist
DNS extendida. Cobre os gaps deixados pelo pentest_avancado.py quando as
fontes externas estao com rate limit ou timeout.

Roda em sequencia:
    1. Re-tenta crt.sh / AlienVault / Anubis com User-Agent de browser
    2. Brute-force DNS extendido (~250 prefixos) para o apex e mobile
    3. Resolve cada nome candidato e marca CDN/origem
    4. Executa wfuzz "lite" em paths comuns sobre ds e m
    5. Faz GET na home e captura headers, server, set-cookie
    6. Persiste tudo em descoberta_full.json
"""
from __future__ import annotations

import concurrent.futures as cf
import gzip
import io
import ipaddress
import json
import socket
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

# Imports do toolkit
from toolkit.discovery import waf_fingerprint
from toolkit.discovery.origin_finder import _classify_cdn  # noqa: PLC2701

# ============================================================
# CONFIG
# ============================================================
APEX = "amizade777.com"
TARGETS = ["ds.amizade777.com", "m.amizade777.com"]
OUTPUT = ROOT / "descoberta_full.json"

UA_BROWSER = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
HTTP_TIMEOUT = 30.0

# Wordlist DNS expandida.  Mistura prefixos academicos, financeiros, dev e
# operacionais.  ~250 entradas, suficiente para encontrar ambientes
# "ocultos" sem martelar excessivamente o DNS.
DNS_WORDLIST = [
    # Web / app
    "www", "m", "ds", "dt", "mb", "app", "api", "api2", "api-v2", "rest",
    "graphql", "ws", "wss", "websocket", "socket", "static", "cdn", "cdn1",
    "assets", "img", "image", "images", "media", "files", "file", "upload",
    "uploads", "download", "downloads", "static1", "static2", "img1", "img2",
    # Auth
    "auth", "login", "sso", "oauth", "id", "account", "accounts", "user",
    "users", "register", "signup", "signin",
    # Admin / mgmt
    "admin", "adm", "administrator", "manage", "manager", "panel", "painel",
    "dashboard", "ops", "control", "console", "operator", "staff",
    "superadmin", "backoffice", "internal", "intranet", "extranet",
    # Dev / staging
    "dev", "develop", "development", "test", "testing", "qa", "uat",
    "staging", "stage", "homolog", "hml", "preview", "demo", "beta", "alpha",
    "sandbox", "lab", "labs",
    # Cassino-specific
    "casino", "slot", "slots", "bet", "bets", "game", "games", "jogo",
    "jogos", "play", "promo", "promocao", "bonus", "vip", "agent", "afiliado",
    "afiliados", "agente", "agentes", "operator", "operators", "wallet",
    "carteira", "saque", "deposito", "pix", "pagamento", "payment", "pay",
    "checkout",
    # Mobile
    "mobile", "wap", "android", "ios", "apk", "app1", "app2",
    # Versionamento
    "v1", "v2", "v3", "old", "new", "next", "legacy",
    # Servicos
    "mail", "webmail", "smtp", "imap", "pop", "ftp", "sftp", "vpn", "remote",
    "rdp", "ssh", "git", "gitlab", "jenkins", "ci", "cd", "drone",
    # Infra
    "ns", "ns1", "ns2", "dns", "mx", "mx1", "mx2", "monitor", "status",
    "stat", "stats", "metrics", "grafana", "kibana", "elastic", "logs",
    "log", "syslog", "prometheus", "alert", "alerts", "siem",
    # Storage / cloud
    "s3", "storage", "store", "backup", "backups", "archive", "archives",
    "cloud", "minio", "redis", "cache", "memcache", "db", "mysql", "postgres",
    "mongo", "elastic", "search", "solr",
    # Conteudo
    "blog", "news", "wiki", "docs", "doc", "support", "help", "kb", "faq",
    "forum", "community",
    # Geo / lang
    "br", "us", "en", "pt", "es", "lat", "latam", "asia", "eu",
    # Aleatorios populares
    "go", "click", "go1", "ad", "ads", "track", "tracking", "analytics",
    "stats1", "metric", "report", "reports", "audit",
    # Aleatorios baixos comuns (numericos)
    "1", "2", "3", "01", "02", "03",
]


# ----------------------------------------------------------------------
# HTTP helper com UA de browser e gzip
# ----------------------------------------------------------------------

def http_get(url: str, *, timeout: float = HTTP_TIMEOUT, headers: dict | None = None) -> tuple[int, dict, bytes]:
    base_headers = {
        "User-Agent": UA_BROWSER,
        "Accept": "application/json, text/html, */*",
        "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8",
        "Accept-Encoding": "gzip, deflate",
    }
    if headers:
        base_headers.update(headers)
    req = Request(url, headers=base_headers)
    with urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        if resp.headers.get("content-encoding") == "gzip":
            raw = gzip.decompress(raw)
        return resp.status, dict(resp.getheaders()), raw


# ----------------------------------------------------------------------
# Fontes passivas com retry
# ----------------------------------------------------------------------

def query_crtsh_with_retry(domain: str, *, attempts: int = 3) -> list[str]:
    print(f"  crt.sh: tentando ate {attempts}x com timeout 60s")
    for i in range(attempts):
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            _, _, body = http_get(url, timeout=60.0)
            data = json.loads(body.decode("utf-8") or "[]")
            found: set[str] = set()
            for entry in data:
                for line in (entry.get("name_value") or "").splitlines():
                    line = line.strip().lstrip("*.").lower()
                    if line and (line == domain or line.endswith("." + domain)):
                        found.add(line)
            print(f"    tentativa {i + 1}: {len(found)} achados")
            return sorted(found)
        except Exception as exc:
            print(f"    tentativa {i + 1} falhou: {type(exc).__name__}: {exc}")
            time.sleep(3 + i * 2)
    return []


def query_alienvault_with_retry(domain: str, *, attempts: int = 3) -> list[str]:
    print(f"  AlienVault OTX: tentando ate {attempts}x com backoff")
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    for i in range(attempts):
        try:
            _, _, body = http_get(url, timeout=20.0)
            data = json.loads(body.decode("utf-8") or "{}")
            found: set[str] = set()
            for rec in data.get("passive_dns") or []:
                host = (rec.get("hostname") or "").lower()
                if host == domain or host.endswith("." + domain):
                    found.add(host)
            print(f"    tentativa {i + 1}: {len(found)} achados")
            return sorted(found)
        except Exception as exc:
            print(f"    tentativa {i + 1} falhou: {type(exc).__name__}: {exc}")
            time.sleep(5 + i * 4)
    return []


def query_hackertarget_with_retry(domain: str, *, attempts: int = 2) -> list[str]:
    print(f"  HackerTarget: tentando ate {attempts}x")
    for i in range(attempts):
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            _, _, body = http_get(url, timeout=20.0)
            text = body.decode("utf-8")
            if "API count exceeded" in text or "error check" in text.lower():
                print(f"    tentativa {i + 1}: rate limited")
                time.sleep(4 + i * 4)
                continue
            found = set()
            for line in text.splitlines():
                host = line.split(",", 1)[0].strip().lower()
                if host == domain or host.endswith("." + domain):
                    found.add(host)
            print(f"    tentativa {i + 1}: {len(found)} achados")
            return sorted(found)
        except Exception as exc:
            print(f"    tentativa {i + 1} falhou: {type(exc).__name__}: {exc}")
            time.sleep(3 + i * 2)
    return []


# ----------------------------------------------------------------------
# Brute force DNS paralelo
# ----------------------------------------------------------------------

def resolve_one(name: str) -> tuple[str, list[str]]:
    try:
        infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
        ips = sorted({info[4][0] for info in infos})
        return name, ips
    except OSError:
        return name, []


def dns_bruteforce(apex: str, wordlist: list[str], *, workers: int = 30) -> dict[str, list[str]]:
    print(f"  brute force DNS de {len(wordlist)} prefixos sobre {apex} ({workers} threads)")
    candidates = [f"{p}.{apex}" for p in wordlist]
    found: dict[str, list[str]] = {}
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for name, ips in ex.map(resolve_one, candidates):
            if ips:
                found[name] = ips
                print(f"    [OK] {name} -> {', '.join(ips)}")
    return found


# ----------------------------------------------------------------------
# Probe HTTP simples
# ----------------------------------------------------------------------

def probe_target(target: str) -> dict:
    print(f"\n  probe HTTP em https://{target}/")
    out: dict = {"target": target, "url": f"https://{target}/", "status": None,
                 "headers": {}, "set_cookie": [], "waf": None, "body_len": 0}
    try:
        status, headers, body = http_get(f"https://{target}/", timeout=15.0)
        out["status"] = status
        out["headers"] = headers
        out["body_len"] = len(body)
        cookies: list[str] = []
        sc = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
        if sc:
            for piece in sc.split(","):
                name = piece.split("=", 1)[0].strip()
                if name:
                    cookies.append(name)
        out["set_cookie"] = cookies
        fp = waf_fingerprint.fingerprint(headers, cookies=cookies)
        out["waf"] = fp.to_dict()
        print(f"    {target}: status={status} bytes={len(body)} waf={fp.detected}")
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        print(f"    {target}: erro {exc}")
    return out


# ----------------------------------------------------------------------
# Probe de paths sensíveis
# ----------------------------------------------------------------------

SENSITIVE_PATHS = [
    "/.git/config", "/.git/HEAD", "/.env", "/.env.local", "/.env.production",
    "/config.json", "/config.js", "/config.php", "/composer.json",
    "/package.json", "/package-lock.json", "/yarn.lock", "/Dockerfile",
    "/.dockerignore", "/docker-compose.yml", "/.aws/credentials", "/.npmrc",
    "/.htaccess", "/web.config", "/server-status", "/server-info",
    "/phpinfo.php", "/info.php", "/test.php", "/health", "/healthz",
    "/healthcheck", "/status", "/metrics", "/actuator", "/actuator/health",
    "/actuator/env", "/actuator/heapdump", "/actuator/mappings",
    "/swagger-ui.html", "/swagger", "/swagger.json", "/v2/api-docs",
    "/v3/api-docs", "/api-docs", "/api/swagger", "/openapi.json",
    "/robots.txt", "/sitemap.xml", "/manifest.json", "/security.txt",
    "/.well-known/security.txt", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/admin", "/admin/", "/admin/login", "/manage", "/manager",
    "/console", "/login.json", "/api", "/api/", "/api/v1", "/api/v2",
    "/prod-api/", "/japi/", "/staging-api/", "/dev-api/", "/test-api/",
    "/internal", "/debug", "/debug.log", "/error.log", "/access.log",
    "/backup", "/backup.zip", "/backup.tar.gz", "/dump.sql", "/db.sql",
    "/.svn/entries", "/.hg/", "/.bzr/", "/CVS/Entries",
    "/wp-admin/", "/wp-login.php", "/wp-config.php",
    "/.DS_Store", "/Thumbs.db", "/desktop.ini",
]


def probe_sensitive_paths(target: str, paths: list[str], *, workers: int = 20) -> list[dict]:
    print(f"\n  probe de {len(paths)} paths sensiveis em https://{target}/")
    results = []

    def fetch(path: str) -> dict:
        url = f"https://{target}{path}"
        try:
            status, headers, body = http_get(url, timeout=10.0)
            ctype = headers.get("Content-Type") or headers.get("content-type") or ""
            return {
                "path": path,
                "status": status,
                "size": len(body),
                "ctype": ctype.split(";")[0].strip(),
                "interesting": status in (200, 401, 403, 500) and len(body) > 0,
            }
        except HTTPError as exc:
            return {"path": path, "status": exc.code, "size": 0, "ctype": "",
                    "interesting": exc.code in (401, 403, 500)}
        except Exception as exc:  # noqa: BLE001
            return {"path": path, "status": None, "error": f"{type(exc).__name__}", "interesting": False}

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(fetch, paths):
            results.append(r)

    interesting = [r for r in results if r.get("interesting")]
    print(f"    {len(interesting)}/{len(results)} paths interessantes")
    for r in interesting:
        print(f"      {r['status']:>3} {r['path']:<40s} {r.get('size', 0):>8d}b  {r.get('ctype', '')}")
    return results


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main() -> None:
    out: dict = {"apex": APEX, "targets": TARGETS}

    print("\n[1/5] FONTES PASSIVAS COM RETRY")
    crtsh = query_crtsh_with_retry(APEX)
    av = query_alienvault_with_retry(APEX)
    ht = query_hackertarget_with_retry(APEX)

    out["passive_sources"] = {
        "crtsh": crtsh,
        "alienvault": av,
        "hackertarget": ht,
    }

    print("\n[2/5] BRUTE FORCE DNS EXTENDIDO")
    bf = dns_bruteforce(APEX, DNS_WORDLIST)
    out["dns_bruteforce"] = bf

    # Combine all and resolve
    all_subs = set(crtsh + av + ht + list(bf.keys()) + TARGETS + [APEX])
    print(f"\n[3/5] RESOLVENDO {len(all_subs)} CANDIDATOS UNICOS")
    resolved: dict[str, dict] = {}
    for name in sorted(all_subs):
        _, ips = resolve_one(name)
        if not ips:
            continue
        cdns = sorted({_classify_cdn(ip) or "unknown" for ip in ips})
        resolved[name] = {"ips": ips, "cdn": cdns}
        marker = ""
        if "unknown" in cdns:
            marker = "  <-- POSSIVEL ORIGEM"
        print(f"  {name:<40s} -> {', '.join(ips)}  [{','.join(cdns)}]{marker}")
    out["resolved"] = resolved

    print("\n[4/5] PROBE HTTP NOS ALVOS PRINCIPAIS")
    probes = []
    for t in TARGETS:
        probes.append(probe_target(t))
    out["http_probes"] = probes

    print("\n[5/5] PROBE DE PATHS SENSIVEIS")
    sensitive = {}
    for t in TARGETS:
        sensitive[t] = probe_sensitive_paths(t, SENSITIVE_PATHS)
    out["sensitive_paths"] = sensitive

    # Resumo
    print("\n=================== RESUMO ===================")
    promising_origins = [
        (name, info) for name, info in resolved.items()
        if "unknown" in info["cdn"]
    ]
    print(f"  Subdominios resolvidos:    {len(resolved)}")
    print(f"  Subdominios atras de CDN:  {len(resolved) - len(promising_origins)}")
    print(f"  Possiveis IPs de origem:   {len(promising_origins)}")
    if promising_origins:
        for name, info in promising_origins:
            print(f"    {name}  ->  {info['ips']}")
    interesting_paths = sum(
        sum(1 for r in lst if r.get("interesting"))
        for lst in sensitive.values()
    )
    print(f"  Paths interessantes:       {interesting_paths}")

    OUTPUT.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n  Resultado salvo em: {OUTPUT}")


if __name__ == "__main__":
    main()

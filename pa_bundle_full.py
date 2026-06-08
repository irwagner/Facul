"""
Pega TODOS os bundles do pa.rainha777slots.com (painel de agentes) usando
o regex correto (eles estao em /static/js/<hash>.js e referenciados como
chunks no webpack runtime). Extrai endpoints, configuracoes e secrets.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))
BUNDLES_DIR = ROOT / "bundles"
BUNDLES_DIR.mkdir(exist_ok=True)

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"


def fetch(url, *, timeout=45.0):
    req = Request(url, headers={"User-Agent": UA, "Accept-Encoding": "gzip"})
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


HOST = "pa.rainha777slots.com"


def main():
    # 1. HTML home
    s, _, b = fetch(f"https://{HOST}/")
    html = b.decode("utf-8", errors="replace")

    # 2. Extrair bundles do <link href=...> e <script src=...> com formato sem aspas (webpack output)
    asset_paths = set()
    for m in re.findall(r'(?:href|src)\s*=\s*([^\s>]+\.(?:js|css))', html):
        # Tira aspas se tiverem
        m = m.strip('"\'')
        asset_paths.add(m)
    print(f"  bundles iniciais: {len(asset_paths)}")
    for p in asset_paths:
        print(f"    {p}")

    # 3. Lista de chunks do webpack runtime (eles ficam em mapa hardcoded no inline)
    # Padrao: "chunk-XXX":"hashYYYY"
    chunks = {}
    for m in re.findall(r'"(chunk-[a-zA-Z0-9]+)":"([a-zA-Z0-9]+)"', html):
        chunks[m[0]] = m[1]
    print(f"\n  chunks no runtime: {len(chunks)}")
    # Adicionar chunks como /static/js/<chunk>.<hash>.js
    for chunk, h in chunks.items():
        asset_paths.add(f"/static/js/{chunk}.{h}.js")
        asset_paths.add(f"/static/css/{chunk}.{h}.css")  # alguns chunks tem css
    print(f"  total bundles a baixar: {len(asset_paths)}")

    # 4. Baixar todos
    bundles_info = []
    js_chunks = []
    for p in sorted(asset_paths):
        url = p if p.startswith("http") else f"https://{HOST}{p}"
        s, _, b = fetch(url, timeout=45)
        if s != 200 or not b:
            print(f"  [{s}] {url}")
            continue
        text = b.decode("utf-8", errors="replace")
        sha = hashlib.sha256(b).hexdigest()[:16]
        fname = url.rsplit("/", 1)[-1]
        local = BUNDLES_DIR / f"pa.rainha777slots.com_{fname}"
        local.write_bytes(b)
        bundles_info.append({"url": url, "size": len(b), "sha": sha, "saved": local.name})
        if url.endswith(".js"):
            js_chunks.append(text)
        print(f"  [{s}] {url} ({len(b)} bytes, sha={sha})")

    merged = "\n".join(js_chunks)
    print(f"\n  total {len(merged):,} chars de JS unificado")

    # 5. Endpoints
    api_paths = sorted(set(re.findall(
        r'["\'](/(?:api|admin|manage|operator|agent|backoffice|aapi|prod-api|japi|adm)/[a-zA-Z0-9_\-/\.]{1,200})["\']',
        merged,
    )))
    print(f"\n  api endpoints: {len(api_paths)}")
    for p in api_paths[:60]:
        print(f"    {p}")

    # 6. config base url
    base_urls = sorted(set(re.findall(
        r'(?:VUE_APP_BASE_API|VITE_BASE_API|baseURL|BASE_URL|api_base|apiBase|VITE_[A-Z_]+|VUE_APP_[A-Z_]+)\s*[:=]\s*["\']([^"\']+)["\']',
        merged,
    )))
    print(f"\n  baseURLs: {base_urls}")

    # 7. Procurar por process.env.<X> referencias
    env_refs = sorted(set(re.findall(r'process\.env\.([A-Z_][A-Z0-9_]+)', merged)))
    print(f"\n  process.env refs: {env_refs}")

    # 8. Secrets
    aws_keys = sorted(set(re.findall(r"\bAKIA[0-9A-Z]{16}\b", merged)))
    google_keys = sorted(set(re.findall(r"\bAIza[0-9A-Za-z\-_]{35}\b", merged)))
    pem_keys = sorted(set(re.findall(r"-----BEGIN [A-Z ]+PRIVATE KEY-----", merged)))
    print(f"\n  AWS keys: {len(aws_keys)} | Google keys: {len(google_keys)} | PEM: {len(pem_keys)}")

    # 9. Dominios externos
    full_urls = sorted(set(re.findall(
        r'["\']https?://[a-zA-Z0-9\-\.]+(?::\d+)?[a-zA-Z0-9_\-/\.\?=&]{0,200}["\']',
        merged,
    )))
    domains = sorted({
        u.strip('"\'').split("//", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
        for u in full_urls
    })
    print(f"\n  dominios externos referenciados:")
    for d in domains[:30]:
        print(f"    {d}")

    # 10. Procurar por funcoes de login / role
    role_keywords = ["role", "agent", "operator", "admin", "permission", "menu",
                     "router", "route", "/login", "/logout", "withdraw", "deposit"]
    role_hits = {}
    for kw in role_keywords:
        cnt = len(re.findall(rf'\b{kw}[a-zA-Z]*\b', merged, re.IGNORECASE))
        role_hits[kw] = cnt
    print(f"\n  keywords:")
    for kw, n in role_hits.items():
        print(f"    {kw}: {n}")

    # 11. Procurar tabelas de menu
    menu_re = re.compile(r'meta\s*:\s*\{\s*title\s*:\s*["\']([^"\']+)["\']', re.IGNORECASE)
    menu_titles = sorted(set(menu_re.findall(merged)))
    print(f"\n  titulos de menu/rota: {len(menu_titles)}")
    for t in menu_titles[:50]:
        print(f"    {t}")

    # 12. Procurar paths de rota
    path_re = re.compile(r'path\s*:\s*["\'](/[a-zA-Z0-9_\-/]{1,80})["\']')
    routes = sorted(set(path_re.findall(merged)))
    print(f"\n  rotas vue-router: {len(routes)}")
    for r in routes[:50]:
        print(f"    {r}")

    out = {
        "host": HOST,
        "bundles_count": len(bundles_info),
        "bundles": bundles_info,
        "merged_size": len(merged),
        "api_endpoints": api_paths,
        "base_urls": base_urls,
        "env_refs": env_refs,
        "aws_keys": aws_keys,
        "google_keys": google_keys,
        "pem_keys": pem_keys,
        "external_domains": domains,
        "role_keyword_hits": role_hits,
        "menu_titles": menu_titles,
        "vue_routes": routes,
    }
    Path("pa_bundle_full.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    print("\n  Salvo em pa_bundle_full.json")


if __name__ == "__main__":
    main()

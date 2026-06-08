"""
Analisa os bundles JS da SPA para encontrar rotas de API, tokens, endpoints ocultos.
"""
import urllib.request, ssl, re, json

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def get(url, max_bytes=200000):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            return r.status, dict(r.headers), r.read(max_bytes).decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, {}, ""
    except Exception as ex:
        return 0, {}, str(ex)

bases = ["https://ds.amizade777.com", "https://m.amizade777.com"]

for base in bases:
    print(f"\n{'='*60}")
    print(f"ANALISANDO: {base}")
    print("="*60)

    status, headers, html = get(base + "/")
    print(f"\n[Headers da resposta principal]")
    for h in ["Server", "X-Powered-By", "Content-Security-Policy",
              "X-Frame-Options", "Strict-Transport-Security",
              "X-Content-Type-Options", "Access-Control-Allow-Origin"]:
        val = headers.get(h, headers.get(h.lower(), "AUSENTE"))
        print(f"  {h}: {val}")

    # Extrair scripts JS
    scripts = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', html)
    print(f"\n[Scripts JS encontrados: {len(scripts)}]")
    for s in scripts:
        url_js = s if s.startswith("http") else base + s
        print(f"  {url_js}")

    # Analisar cada bundle JS
    all_routes = set()
    all_urls = set()
    all_keys = set()

    for script_path in scripts[:5]:  # limitar a 5 bundles
        js_url = script_path if script_path.startswith("http") else base + script_path
        print(f"\n  Baixando {js_url}...")
        s2, h2, js = get(js_url)
        if not js:
            print("  -> vazio ou erro")
            continue
        print(f"  -> {len(js)} bytes")

        # Rotas de API
        rotas = re.findall(r'"(/api/[a-zA-Z0-9/_\-{}.]+)"', js)
        rotas += re.findall(r"'(/api/[a-zA-Z0-9/_\-{}.]+)'", js)
        rotas += re.findall(r'`(/api/[a-zA-Z0-9/_\-{}.]+)`', js)
        all_routes.update(rotas)

        # URLs completas
        urls = re.findall(r'https?://[a-zA-Z0-9._\-/:%?=&]+', js)
        all_urls.update([u for u in urls if "amizade" in u or "localhost" in u])

        # Possíveis chaves/tokens hardcoded
        keys = re.findall(r'(?:apiKey|api_key|API_KEY|secret|token|key|password|senha|pass)["\s:=]+["\']([A-Za-z0-9_\-./+=]{8,})["\']', js, re.IGNORECASE)
        all_keys.update(keys)

        # Variáveis de ambiente
        envs = re.findall(r'VITE_[A-Z_]+=([^\s"\'&]+)', js)
        if envs:
            print(f"  Variáveis VITE_: {envs}")

    print(f"\n[Rotas de API encontradas nos bundles: {len(all_routes)}]")
    for r in sorted(all_routes):
        # Testar se a rota existe
        st, _, _ = get(base + r)
        print(f"  [{st}] {r}")

    print(f"\n[URLs internas encontradas: {len(all_urls)}]")
    for u in sorted(all_urls):
        print(f"  {u}")

    if all_keys:
        print(f"\n[POSSÍVEIS SEGREDOS HARDCODED: {len(all_keys)}]")
        for k in sorted(all_keys):
            print(f"  {k[:4]}***{k[-4:] if len(k) > 8 else '****'}")

print("\n\nConcluído.")

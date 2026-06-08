"""
Extração profunda de rotas de API e URLs do bundle JS principal.
O bundle está minificado — busca padrões mais amplos.
"""
import urllib.request, ssl, re

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def get_full(url):
    chunks = []
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                chunks.append(chunk.decode("utf-8", "ignore"))
    except Exception as ex:
        pass
    return "".join(chunks)

# Bundles principais (mais pesados = mais rotas)
bundles = {
    "ds": "https://ds.amizade777.com/assets/index.76929613.js",
    "m":  "https://m.amizade777.com/assets/index-e7dd841c.js",
}

for nome, url in bundles.items():
    print(f"\n{'='*60}")
    print(f"Bundle: {nome} — {url}")
    print("="*60)
    js = get_full(url)
    print(f"Tamanho total: {len(js):,} bytes")

    # 1. Qualquer string que começa com / e parece uma rota
    rotas_api = set(re.findall(r'["\`](/(?:api|v\d|auth|user|account|pay|wallet|admin)[^\s"\'`<>]{2,60})["\`]', js))
    rotas_api.update(re.findall(r'["\`](/[a-zA-Z][a-zA-Z0-9_\-/]{3,50}(?:login|register|deposit|withdraw|transfer|balance|wallet|user|admin|auth|account|transaction)[^"\`\s<>]{0,30})["\`]', js))

    # 2. URLs absolutas
    urls_abs = set(re.findall(r'https?://[a-zA-Z0-9._\-]+(?:amizade|localhost|127\.0\.0|192\.168)[a-zA-Z0-9._\-/:%?=&@]{0,100}', js))

    # 3. Possíveis hosts/bases de API
    hosts = set(re.findall(r'["\`]((?:https?://)?[a-zA-Z0-9_\-]+\.amizade777\.com[^"\`\s]{0,50})["\`]', js))
    hosts.update(re.findall(r'baseURL["\s:=]+["\`]([^"\`\s]{5,80})["\`]', js))
    hosts.update(re.findall(r'baseUrl["\s:=]+["\`]([^"\`\s]{5,80})["\`]', js))
    hosts.update(re.findall(r'BASE_URL["\s:=]+["\`]([^"\`\s]{5,80})["\`]', js))
    hosts.update(re.findall(r'apiUrl["\s:=]+["\`]([^"\`\s]{5,80})["\`]', js))
    hosts.update(re.findall(r'API_URL["\s:=]+["\`]([^"\`\s]{5,80})["\`]', js))

    # 4. Tokens/chaves
    tokens = set()
    for pat in [
        r'token["\s:=]+["\`]([A-Za-z0-9_\-./+=]{16,})["\`]',
        r'secret["\s:=]+["\`]([A-Za-z0-9_\-./+=]{8,})["\`]',
        r'password["\s:=]+["\`]([A-Za-z0-9_\-./+=]{6,})["\`]',
        r'Authorization["\s:=]+["\`]([A-Za-z0-9_\-./+=\s]{10,})["\`]',
        r'Bearer\s+([A-Za-z0-9_\-./+=]{20,})',
        r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',  # JWT
    ]:
        tokens.update(re.findall(pat, js, re.IGNORECASE))

    # 5. Variáveis de ambiente Vite
    vite_vars = re.findall(r'VITE_[A-Z_0-9]+["\s:=]+["\`]?([^\s"\'`,;){]{3,80})', js)

    # 6. Padrões de WebSocket
    ws_urls = set(re.findall(r'wss?://[a-zA-Z0-9._\-/:%?=&@]{5,100}', js))

    print(f"\n[Rotas de API: {len(rotas_api)}]")
    for r in sorted(rotas_api):
        print(f"  {r}")

    print(f"\n[URLs absolutas internas: {len(urls_abs)}]")
    for u in sorted(urls_abs):
        print(f"  {u}")

    print(f"\n[Base URLs / API hosts: {len(hosts)}]")
    for h in sorted(hosts):
        print(f"  {h}")

    print(f"\n[WebSockets: {len(ws_urls)}]")
    for w in sorted(ws_urls):
        print(f"  {w}")

    if vite_vars:
        print(f"\n[Variáveis VITE_: {len(vite_vars)}]")
        for v in vite_vars[:20]:
            print(f"  {v}")

    if tokens:
        print(f"\n[TOKENS/SEGREDOS: {len(tokens)}]")
        for t in sorted(tokens):
            masked = t[:6] + "***" + t[-4:] if len(t) > 10 else "***"
            print(f"  {masked}")

print("\n\nConcluído.")

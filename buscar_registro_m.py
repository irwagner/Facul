"""
Extrai o endpoint de registro e login do bundle do m.amizade777.com
"""
import urllib.request, ssl, re

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def get_all(url):
    chunks = []
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
        while True:
            c = r.read(65536)
            if not c: break
            chunks.append(c.decode("utf-8","ignore"))
    return "".join(chunks)

bundle = "https://m.amizade777.com/assets/index-e7dd841c.js"
print(f"Baixando {bundle}...")
js = get_all(bundle)
print(f"Tamanho: {len(js):,} bytes\n")

# Buscar todos os padrões de chamadas HTTP no bundle
print("="*60)
print("CHAMADAS HTTP ENCONTRADAS NO BUNDLE")
print("="*60)

# Padrão: method:"post", url:"..."
calls = re.findall(r'method\s*:\s*["\'](?:post|get|put|delete)["\'][^}]{0,200}url\s*:\s*[`"\']([^`"\'<>]{5,100})[`"\']', js, re.IGNORECASE)
calls += re.findall(r'url\s*:\s*[`"\']\s*[`$"\'{](baseUrl|BASE_URL|/prod-api)[^`"\'<>]{3,80}[`"\']', js)

# Padrão: axios.post("...")  ou  instance.post("...")
calls2 = re.findall(r'(?:axios|instance|http|api|request)\s*[.(]\s*["\']([^"\'<>]{5,80})["\']', js)

# Padrão: url: `/prod-api/...`  com template string
calls3 = re.findall(r'[`"\']([^`"\'<>\s]*(?:sign|login|register|deposit|withdraw|recharge|player|member|finance|wallet|balance|admin|invite|vip)[^`"\'<>\s]{0,50})[`"\']', js)

todos = set()
for c in calls + calls2 + calls3:
    c = c.strip()
    if "/" in c and len(c) > 4 and not c.startswith("http") or "prod-api" in c:
        todos.add(c)

print(f"Rotas com termos financeiros/auth ({len(todos)}):")
for r in sorted(todos)[:80]:
    print(f"  {r}")

# Buscar especificamente register, sign-up, sign-in
print("\n" + "="*60)
print("CONTEXTO DOS TERMOS REGISTER / SIGN-UP / SIGN-IN")
print("="*60)
for termo in ["register", "sign-up", "sign_up", "signup", "sign-in", "sign_in", "signin", "recharge", "withdraw", "deposit"]:
    encontradas = []
    idx = 0
    while len(encontradas) < 4:
        pos = js.find(termo, idx)
        if pos == -1: break
        trecho = js[max(0,pos-150):pos+200].replace("\n"," ").replace("\r","")
        if "url" in trecho.lower() or "api" in trecho.lower() or "prod" in trecho.lower() or "path" in trecho.lower():
            encontradas.append(trecho)
        idx = pos + 1
    if encontradas:
        print(f"\n[{termo}]")
        for t in encontradas[:2]:
            print(f"  ...{t[:300]}...")

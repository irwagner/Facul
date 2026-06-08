"""
Busca o AppPackageName e parâmetros ocultos do login no bundle JS.
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
        print(f"Erro: {ex}")
    return "".join(chunks)

bundle_url = "https://ds.amizade777.com/assets/index.76929613.js"
print(f"Baixando bundle: {bundle_url}")
js = get_full(bundle_url)
print(f"Tamanho: {len(js):,} bytes\n")

# Termos a buscar no bundle
termos = [
    "AppPackageName", "appPackageName", "app_package", "packageName",
    "AppId", "appId", "app_id", "clientId", "client_id",
    "deviceId", "device_id", "fingerprint",
    "channel", "platform", "source",
    "sign", "signature", "nonce", "timestamp",
    "headers", "Authorization",
    "prod-api", "baseURL", "baseUrl", "API_URL",
    "login", "mobile", "phone", "username",
    "password", "passwd", "pwd",
]

print("="*55)
for termo in termos:
    # Busca o termo e mostra o contexto ao redor (80 chars)
    idx = 0
    ocorrencias = []
    while True:
        pos = js.find(termo, idx)
        if pos == -1:
            break
        inicio = max(0, pos - 60)
        fim = min(len(js), pos + len(termo) + 80)
        trecho = js[inicio:fim].replace("\n", " ").replace("\r", "")
        ocorrencias.append(trecho)
        idx = pos + 1
        if len(ocorrencias) >= 3:  # máximo 3 ocorrências por termo
            break
    if ocorrencias:
        print(f"\n[{termo}] ({len(ocorrencias)} ocorrência(s))")
        for oc in ocorrencias[:3]:
            print(f"  ...{oc}...")

print("\n\nBusca de campos do login:")
print("="*55)
# Buscar especificamente o objeto de requisição do login
login_contexts = []
idx = 0
while True:
    pos = js.find("login", idx)
    if pos == -1:
        break
    trecho = js[max(0,pos-200):pos+300].replace("\n"," ")
    if "post" in trecho.lower() or "axios" in trecho.lower() or "fetch" in trecho.lower() or "request" in trecho.lower():
        login_contexts.append(trecho)
    idx = pos + 1
    if len(login_contexts) >= 5:
        break

for ctx_login in login_contexts:
    print(f"\n  {ctx_login[:300]}")
    print("  ---")

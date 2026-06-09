"""
Análise profunda de superfícies ainda não exploradas:
1. PA bundle chunks completos (rotas, permissões, APIs)
2. WebSocket (protobuf decode + auth)
3. DNS/subdomínios não testados
4. APK DEX (strings com endpoints)
5. Megaslott (3o tenant)
6. Novos tenants descobertos via DNS
"""
import re, json, os, glob, ssl, urllib.request, urllib.error, time, struct
from collections import Counter, defaultdict

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

# ═══════════════════════════════════════════════════════
# PARTE 1 — PA bundle: rotas, APIs, permissões
# ═══════════════════════════════════════════════════════

print("=" * 60)
print("PARTE 1 — PA BUNDLE COMPLETO")
print("=" * 60)

pa_js_files = glob.glob("pa_bundles/*.js")
all_content = ""
for fp in pa_js_files:
    try:
        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
            all_content += f.read() + "\n"
    except: pass

print(f"  Total JS PA: {len(all_content):,} chars em {len(pa_js_files)} arquivos")

# Rotas Vue
routes = re.findall(r'path:\s*["\']([/A-Za-z0-9_\-:]{2,60})["\']', all_content)
routes_unique = sorted(set(r for r in routes if r.startswith("/")))
print(f"\n  Rotas Vue ({len(routes_unique)}):")
for r in routes_unique:
    print(f"    {r}")

# Endpoints API
apis = set()
for m in re.finditer(r'url:\s*["\`]([^"\`\n ]{5,120})["\`]', all_content):
    v = m.group(1)
    if any(k in v for k in ("/prod-api","/japi","/api","/system","/invite","/user")):
        apis.add(v.strip())
print(f"\n  Endpoints API ({len(apis)}):")
for a in sorted(apis):
    print(f"    {a}")

# Strings de roles/permissões
role_patterns = re.findall(
    r'["\']([a-zA-Z_]*(?:admin|role|perm|super|agent|operator|manager|staff)[a-zA-Z_]*)["\']',
    all_content, re.I)
role_counter = Counter(role_patterns)
print(f"\n  Roles/permissões encontradas:")
for role, cnt in role_counter.most_common(15):
    print(f"    {role!r}: {cnt}x")

# Strings que parecem secrets/tokens
secret_patterns = re.findall(
    r'(?:secret|apiKey|privateKey|signing|hmac|jwt|aes)["\s=:]+["\']([^"\']{8,60})["\']',
    all_content, re.I)
if secret_patterns:
    print(f"\n  Possíveis secrets:")
    for s in secret_patterns[:10]:
        if s not in ("undefined","null","Bearer",""):
            print(f"    {s!r}")

# Buscar lógica de autenticação do PA (como ele valida o token)
auth_ctx = []
for m in re.finditer(r'.{0,100}(?:token|Authorization|Bearer|auth).{0,100}', all_content, re.I):
    auth_ctx.append(m.group(0)[:200])
if auth_ctx:
    print(f"\n  Contextos de auth ({len(auth_ctx)}):")
    seen = set()
    for ctx_str in auth_ctx[:20]:
        if ctx_str[:50] not in seen:
            seen.add(ctx_str[:50])
            print(f"    {ctx_str[:200]!r}")

# ═══════════════════════════════════════════════════════
# PARTE 2 — WebSocket: análise do protocolo protobuf
# ═══════════════════════════════════════════════════════

print("\n" + "=" * 60)
print("PARTE 2 — WEBSOCKET & PROTOBUF")
print("=" * 60)

# O WebSocket usa protobuf. O frame capturado tinha:
# {"msgtype": 1, "msg": "CJHZgcTqMw=="}
# msg decodificado = 0891d981c4ea33 = varint(1780943449233) no campo 1
# Esse é provavelmente um timestamp Unix (ms) — heartbeat

# O JS tem message.js que define os tipos de mensagem
for fp in glob.glob("bundles/ds.amizade777.com_message.js"):
    with open(fp, "r", encoding="utf-8", errors="ignore") as f:
        msg_content = f.read()
    print(f"  message.js: {len(msg_content)} chars")
    # Extrair msgtype constants
    msgtypes = re.findall(r'(?:msgType|MsgType|MSG_TYPE|type)["\s=:]+(\d{1,5})', msg_content)
    print(f"  msgtype values: {sorted(set(int(x) for x in msgtypes))[:20]}")
    # Extrair nomes de mensagem
    msg_names = re.findall(r'["\']([A-Za-z][A-Za-z0-9_]{5,40}(?:Msg|Message|Request|Response|Notify|Push))["\']', msg_content)
    if msg_names:
        print(f"  Tipos de mensagem: {sorted(set(msg_names))[:20]}")
    print(f"  Amostra:\n{msg_content[:1000]}")

# Verificar se WS aceita conexão sem auth
for ws_host in ["ds.amizade777.com", "ds.rainha777slots.com"]:
    for ws_path in ["/websocket6", "/websocket", "/ws"]:
        url = f"https://{ws_host}{ws_path}"
        h = {"User-Agent": "Mozilla/5.0",
             "Upgrade": "websocket", "Connection": "Upgrade",
             "Sec-WebSocket-Version": "13",
             "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="}
        try:
            r = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(r, timeout=5, context=ctx) as resp:
                print(f"  {ws_host}{ws_path}: HTTP {resp.status} (WS upgrade?)")
        except urllib.error.HTTPError as e:
            if e.code == 101:
                print(f"  🔴 {ws_host}{ws_path}: HTTP 101 — WebSocket ABERTO SEM AUTH!")
            else:
                print(f"  {ws_host}{ws_path}: HTTP {e.code}")
        except Exception as ex:
            pass
        time.sleep(0.3)

# ═══════════════════════════════════════════════════════
# PARTE 3 — Megaslott e outros tenants não testados
# ═══════════════════════════════════════════════════════

print("\n" + "=" * 60)
print("PARTE 3 — OUTROS TENANTS (megaslott, lucky777, aphrodite)")
print("=" * 60)

tenants = [
    ("megaslott",   "sx.megaslott.com"),
    ("megaslott_ds","ds.megaslott.com"),
    ("lucky777_mx", "ds.lucky777.mx"),
    ("aphrodite",   "ds.aphrodite777.com"),
    ("ccgamevip",   "hus3wyear.ccgamevip.com"),
]

def test_tenant(host):
    results = {}
    # Ping
    try:
        r = urllib.request.Request(f"https://{host}/", headers={"User-Agent":"Mozilla/5.0"})
        with urllib.request.urlopen(r, timeout=5, context=ctx) as resp:
            results["ping"] = resp.status
    except urllib.error.HTTPError as e:
        results["ping"] = e.code
    except Exception:
        results["ping"] = 0

    if results["ping"] == 0:
        return results

    # Token anão
    try:
        h = {"Token":"1","User-Agent":"Mozilla/5.0","Accept":"application/json"}
        r = urllib.request.Request(f"https://{host}/japi/user/balance/querySimpleBalance", headers=h)
        with urllib.request.urlopen(r, timeout=5, context=ctx) as resp:
            b = json.loads(resp.read())
            results["dwarf_token"] = {"code": b.get("code"), "data": b.get("data")}
    except Exception as ex:
        results["dwarf_token"] = {"err": str(ex)[:50]}

    time.sleep(0.5)

    # Config dump sem auth
    try:
        payload = json.dumps({"appChannel":"pc","appVersion":"1.0.0","appPackageName":"com.slots.big"}).encode()
        h = {"Content-Type":"application/json","User-Agent":"Mozilla/5.0","Accept":"application/json"}
        r = urllib.request.Request(f"https://{host}/prod-api/set/get", data=payload, headers=h, method="POST")
        with urllib.request.urlopen(r, timeout=5, context=ctx) as resp:
            b = json.loads(resp.read())
            d = b.get("data") or {}
            results["config_dump"] = {
                "code": b.get("code"),
                "ipWhites": (d.get("ab_condition") or {}).get("ipWhites"),
                "withdraw_min": d.get("withdraw_min"),
                "ip_user_limit": d.get("ip_user_limit"),
            }
    except Exception as ex:
        results["config_dump"] = {"err": str(ex)[:50]}

    return results

for name, host in tenants:
    print(f"\n  {name} ({host}):")
    r = test_tenant(host)
    for k, v in r.items():
        print(f"    {k}: {v}")

# ═══════════════════════════════════════════════════════
# PARTE 4 — Subdomínios descobertos mas não testados
# ═══════════════════════════════════════════════════════

print("\n" + "=" * 60)
print("PARTE 4 — SUBDOMÍNIOS NÃO TESTADOS")
print("=" * 60)

# Carrega o pentest_avancado para ver quais subdomínios descobriu
try:
    with open("pentest_avancado_amizade777_com.json", encoding="utf-8") as f:
        recon = json.load(f)
    subdomains = recon.get("subdomains", {}).get("all", [])
    print(f"  Total subdomínios conhecidos: {len(subdomains)}")
    # Filtrar os que não testamos ainda
    tested = {"ds.amizade777.com","m.amizade777.com","pa.rainha777slots.com",
              "ds.rainha777slots.com","api.rainha777slots.com"}
    untested = [s for s in subdomains if s not in tested and "amizade" in s.lower()]
    print(f"  Não testados: {len(untested)}")
    for s in untested[:20]:
        print(f"    {s}")

    # IPs de origem candidatos
    candidates = recon.get("origin_candidates", {}).get("promising", [])
    print(f"\n  IPs de origem candidatos: {len(candidates)}")
    for ip in candidates[:10]:
        print(f"    {ip}")
except Exception as ex:
    print(f"  [erro: {ex}]")

# ═══════════════════════════════════════════════════════
# PARTE 5 — APK DEX — extrair strings com endpoints
# ═══════════════════════════════════════════════════════

print("\n" + "=" * 60)
print("PARTE 5 — APK DEX — strings com endpoints")
print("=" * 60)

dex_path = "apk_extracted/classes.dex"
if os.path.exists(dex_path):
    with open(dex_path, "rb") as f:
        dex_data = f.read()

    # Extrair strings legíveis do DEX (strings ASCII de 8-120 chars)
    strings = re.findall(rb'[\x20-\x7e]{8,120}', dex_data)
    api_strings = []
    for s in strings:
        try:
            decoded = s.decode("ascii", errors="ignore")
            if any(k in decoded for k in ("/prod-api/","/japi/","/api/","http://","https://")):
                api_strings.append(decoded)
        except: pass

    print(f"  Strings API no DEX: {len(api_strings)}")
    seen = set()
    for s in api_strings:
        if s not in seen:
            seen.add(s)
            print(f"    {s}")
else:
    print("  DEX não encontrado. Tentando extrair diretamente do APK...")
    # Tentar ler o APK como zip
    import zipfile
    if os.path.exists("Amizade777.apk"):
        try:
            with zipfile.ZipFile("Amizade777.apk") as z:
                for name in z.namelist():
                    if name.endswith(".dex"):
                        data = z.read(name)
                        strings_dex = re.findall(rb'[\x20-\x7e]{8,120}', data)
                        found = 0
                        for s in strings_dex:
                            decoded = s.decode("ascii","ignore")
                            if any(k in decoded for k in ("/prod-api/","/japi/","/api/","http://")):
                                print(f"    {decoded}")
                                found += 1
                                if found > 50: break
        except Exception as ex:
            print(f"  [erro APK: {ex}]")

print("\nConcluído.")

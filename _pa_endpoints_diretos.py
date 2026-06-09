"""Testa endpoints do PA de forma direta, incluindo token anão."""
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
        with urllib.request.urlopen(r, timeout=8, context=ctx) as resp:
            raw = resp.read(8192).decode("utf-8","ignore")
            try: return resp.status, json.loads(raw)
            except: return resp.status, {"_raw": raw[:200]}
    except urllib.error.HTTPError as e:
        raw = e.read(4096).decode("utf-8","ignore") if e.fp else ""
        try: return e.code, json.loads(raw)
        except: return e.code, {"_raw": raw[:200]}
    except Exception as ex:
        return 0, {"err": str(ex)}

print("=" * 60)
print("PA — Mapear qual prefixo de API responde JSON")
print("=" * 60)

# O PA tem baseURL=/prod-api mas pode servir /japi também
prefixes = ["/prod-api", "/japi", "/api", ""]
test_suffix = "/system/user/gsf/login"
body_test = {"username": "admin", "password": "admin"}

for pfx in prefixes:
    st, b = call("POST", pfx + test_suffix, body_test)
    code = b.get("code") if isinstance(b,dict) else None
    raw  = b.get("_raw","")[:100] if isinstance(b,dict) else ""
    print(f"  POST {pfx+test_suffix}: HTTP={st} code={code} raw={raw!r}")
    time.sleep(0.3)

print()
print("=" * 60)
print("PA — Token anão nos endpoints que o JS referenciou")
print("=" * 60)

# Esses endpoints vieram do JS do PA com baseURL=/prod-api
pa_endpoints = [
    ("/prod-api/invite/admin/invite/getUserInviteList",       "GET"),
    ("/prod-api/invite/admin/invite/getInviteConfig",         "GET"),
    ("/prod-api/invite/admin/invite/getRewardRecordList",     "GET"),
    ("/prod-api/invite/admin/invite/queryInviteDayReportData","POST"),
    ("/prod-api/invite/admin/invite/queryInviteRewardData",   "POST"),
    ("/prod-api/system/user/gsf/info",                        "GET"),
    ("/prod-api/system/user/gsf/getUserList",                 "GET"),
    ("/prod-api/system/user/info",                            "GET"),
    # Tentar com /japi também
    ("/japi/invite/admin/invite/getUserInviteList",           "GET"),
    ("/japi/system/user/info",                                "GET"),
]

for path, method in pa_endpoints:
    # Sem token
    if method == "GET":
        st0, b0 = call("GET", path)
    else:
        st0, b0 = call("POST", path, {"appPackageName":"com.slots.big"})
    c0 = b0.get("code") if isinstance(b0,dict) else None

    # Token anão uid=1
    if method == "GET":
        st1, b1 = call("GET", path, token=1)
    else:
        st1, b1 = call("POST", path, {"appPackageName":"com.slots.big"}, token=1)
    c1 = b1.get("code") if isinstance(b1,dict) else None
    d1 = b1.get("data") if isinstance(b1,dict) else None

    if c1 == 200 or c0 == 200:
        flag = "🔴 ACEITO" if c1 == 200 else "🟡 público"
        print(f"  {flag} [{method}] {path}")
        if d1: print(f"    data={json.dumps(d1, ensure_ascii=False)[:300]}")
    elif c1 not in (None, 401, 403, 404, 405, 500, 400):
        print(f"  [{method}] {path} → c0={c0} c1={c1}")
    time.sleep(0.4)

print()
print("=" * 60)
print("PA — Testar se /prod-api/* do PA aponta pro mesmo backend dos jogadores")
print("=" * 60)

# Se o PA serve os MESMOS endpoints de jogo (sign-in etc), é um ponto de entrada diferente
test_game_endpoints = [
    ("POST", "/prod-api/player/sign-in"),
    ("GET",  "/prod-api/set/get"),
    ("POST", "/prod-api/set/get"),
    ("GET",  "/japi/user/balance/querySimpleBalance"),
]
game_body = {"appChannel":"pc","appPackageName":"com.slots.big","appVersion":"1.0.0"}

for method, path in test_game_endpoints:
    if method == "GET":
        st, b = call("GET", path, token=1)
    else:
        st, b = call("POST", path, game_body, token=1)
    code = b.get("code") if isinstance(b,dict) else None
    data = b.get("data") if isinstance(b,dict) else None
    print(f"  [{method} {st}] {path} → code={code} data={str(data)[:100] if data else None}")
    time.sleep(0.3)

print("\nConcluído.")

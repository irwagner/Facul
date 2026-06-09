"""Analisa HTML do PA e baixa bundles JS."""
import urllib.request, ssl, re, json, os, time

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

PA = "https://pa.rainha777slots.com"

def fetch(url, binary=False):
    r = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(r, timeout=15, context=ctx) as resp:
            data = resp.read()
            return resp.status, data if binary else data.decode("utf-8","ignore")
    except Exception as ex:
        return 0, str(ex)

# Pega HTML
st, html = fetch(PA + "/")
print(f"HTML: {len(html)} chars, HTTP={st}")
print(f"Primeiros 2000 chars:")
print(html[:2000])
print()

# Extrai scripts
scripts = re.findall(r'src=["\'](.*?)["\']', html)
links   = re.findall(r'href=["\'](.*?)["\']', html)

print("Scripts:", scripts)
print("Links:", [l for l in links if ".js" in l or ".css" in l])

# Baixa todos os scripts JS
os.makedirs("pa_bundles", exist_ok=True)
all_js = ""
for src in scripts:
    if not src.endswith(".js") and ".js" not in src:
        continue
    url = PA + src if src.startswith("/") else src
    fname = f"pa_bundles/{src.replace('/','_')[-60:]}"
    st2, content = fetch(url)
    if st2 == 200 and len(content) > 100:
        with open(fname, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"[baixou] {src} ({len(content)} chars)")
        all_js += content + "\n"
    else:
        print(f"[ERRO {st2}] {src}")
    time.sleep(0.3)

if not all_js:
    # Tentar paths diretos do SPA
    for p in ["/static/js/app.3bae0f2c.js",
               "/static/js/chunk-libs.cdb414f0.js",
               "/static/js/chunk-elementUI.f92cd1c5.js"]:
        st2, content = fetch(PA + p)
        if st2 == 200 and len(content) > 500:
            print(f"[direto] {p} ({len(content)} chars)")
            fname = f"pa_bundles/{p.replace('/','_')}"
            with open(fname, "w", encoding="utf-8") as f:
                f.write(content)
            all_js += content + "\n"
        time.sleep(0.3)

print(f"\nTotal JS: {len(all_js)} chars")

if all_js:
    # Extrai endpoints
    paths = set()
    for m in re.finditer(r'["\']((/?(?:api|admin|user|system|prod|japi|invite|manage|player|finance|auth)[A-Za-z0-9/_\-\.]{3,80}))["\']', all_js):
        p = m.group(1)
        if not p.startswith("/"): p = "/" + p
        paths.add(p)

    # BaseURL
    for m in re.finditer(r'(baseURL|VUE_APP_BASE_API|process\.env\.[A-Z_]+)\s*[:=]\s*["\`]([^"\`\n]{3,100})["\`]', all_js):
        print(f"  [{m.group(1)}] = {m.group(2)!r}")

    # Credenciais hardcoded
    for m in re.finditer(r'(?:password|passwd|secret|token)["\s]*[:=]["\s]*["\']([^"\']{4,40})["\']', all_js, re.I):
        print(f"  [cred hardcoded?] {m.group(0)[:80]!r}")

    print(f"\nPaths encontrados: {len(paths)}")
    for p in sorted(paths):
        print(f"  {p}")

    with open("pa_endpoints.json","w",encoding="utf-8") as f:
        json.dump({"total": len(paths), "all": sorted(paths)}, f, ensure_ascii=False, indent=2)

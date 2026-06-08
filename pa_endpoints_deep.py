"""
Procura profundamente endpoints HTTP no bundle do pa.rainha777slots.com.
Os endpoints ficam dentro de chamadas axios.get('/...') ou request({url:'/...'}).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BUNDLES = ROOT / "bundles"

# Lê só os bundles do pa.rainha
files = sorted(BUNDLES.glob("pa.rainha777slots.com_*.js"))
if not files:
    print("Sem bundles do pa. rainha")
    sys.exit(0)

text = "\n".join(f.read_text(encoding="utf-8", errors="replace") for f in files)
print(f"Total: {len(text):,} chars de {len(files)} arquivos")

# 1. axios calls
axios_patterns = [
    re.compile(r'(?:axios|api|request|http|service)\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']'),
    re.compile(r"url\s*:\s*[\"']([^\"']+)[\"']"),
    re.compile(r"path\s*:\s*[\"'](/[a-zA-Z][a-zA-Z0-9_\-/]+)[\"']"),
]
all_urls = set()
for p in axios_patterns:
    for m in p.findall(text):
        if m.startswith("/") and len(m) > 3 and len(m) < 200:
            all_urls.add(m)

api_urls = sorted([u for u in all_urls if any(
    seg in u for seg in ("/api/", "/prod-api/", "/japi/", "/admin/", "/agent/",
                          "/operator/", "/manage/", "/auth/", "/user/",
                          "/login", "/logout", "/finance", "/wallet")
)])

print(f"\nEndpoints API: {len(api_urls)}")
for u in api_urls:
    print(f"  {u}")

# 2. Strings que parecem endpoints
all_paths = sorted(all_urls)
print(f"\nTodos os paths/urls (>= 5 chars): {len(all_paths)}")
for u in all_paths[:80]:
    print(f"  {u}")

# 3. Procurar request defaults / interceptors
print("\n=== axios.create config ===")
for m in re.finditer(r"axios\.create\s*\(\s*\{([^}]{1,500})\}", text):
    print(f"  {m.group(1)[:300].replace(chr(10), ' ')}")

# 4. Procurar chamadas internas tipo Vue.prototype.$baseUrl
print("\n=== baseUrl / $api / VUE_APP_ ===")
for m in re.finditer(r"(?:baseUrl|baseURL|VUE_APP_BASE_API|VUE_APP_API|process\.env\.\w+)[^,;]{1,150}", text):
    snippet = m.group(0).replace("\n", " ")
    if len(snippet) < 200:
        print(f"  {snippet[:200]}")

# 5. Procurar tabelas de menu carregadas via API
print("\n=== Menu structure / role logic ===")
for m in re.finditer(r"(?:permission|role|admin|agent|operator)[^,;]{1,80}\?", text, re.IGNORECASE):
    snippet = m.group(0).replace("\n", " ")
    if 5 < len(snippet) < 100:
        print(f"  {snippet}")

# 6. Strings com "login" + "/"
print("\n=== Strings de login ===")
for m in re.finditer(r"['\"]([^'\"]*(?:login|signin|sign-in|auth|token)[^'\"]{0,30})['\"]", text, re.IGNORECASE):
    s = m.group(1)
    if 5 < len(s) < 100 and ("/" in s or "Login" in s):
        print(f"  {s}")

# 7. Procurar i18n locales
print("\n=== Locale file referenced ===")
for m in re.finditer(r"['\"]([a-zA-Z\-]+)\.json['\"]", text):
    print(f"  {m.group(1)}.json")

Path("pa_endpoints_deep.json").write_text(
    json.dumps({
        "api_urls": api_urls,
        "all_paths": all_paths[:200],
    }, indent=2),
    encoding="utf-8",
)

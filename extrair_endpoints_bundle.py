"""Extrai todos os endpoints de API dos bundles JS."""
import re, json, glob, os
from collections import defaultdict

bundles = glob.glob("bundles/ds.amizade777.com_index*.js")
bundles += glob.glob("bundles/ds.amizade777.com_main.js")
bundles += glob.glob("bundles/m.amizade777.com_index*.js")

all_paths = set()
for fp in bundles:
    try:
        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        continue

    # Captura paths de API em strings JS
    # Padrões: "/prod-api/xxx", "/japi/xxx", "/api/xxx"
    found = re.findall(
        r'["\']((/?(?:prod-api|japi|api)/[A-Za-z0-9/_\-\.]{3,80}))["\']',
        content
    )
    for m in found:
        path = m[0] if m[0].startswith("/") else "/" + m[0]
        all_paths.add(path)

# Categorizar
cats = {
    "admin":     [],
    "financeiro": [],
    "auth":      [],
    "user":      [],
    "game":      [],
    "other":     [],
}
for p in sorted(all_paths):
    pl = p.lower()
    if any(x in pl for x in ("admin","manage","system","super","staff",
                              "operator","debug","internal","setting",
                              "config","dashboard","panel","console")):
        cats["admin"].append(p)
    elif any(x in pl for x in ("withdraw","recharge","pay","fund","wallet",
                               "transfer","balance","money","cash","bank",
                               "charge","refund","coupon","bonus")):
        cats["financeiro"].append(p)
    elif any(x in pl for x in ("login","sign","register","token","auth",
                               "password","reset","verify","otp","captcha",
                               "invite","bind")):
        cats["auth"].append(p)
    elif any(x in pl for x in ("user","player","profile","info","account",
                               "vip","level","rank")):
        cats["user"].append(p)
    elif any(x in pl for x in ("game","slot","bet","round","spin","play",
                               "lobby","hall")):
        cats["game"].append(p)
    else:
        cats["other"].append(p)

print(f"Total único: {len(all_paths)}\n")
for cat, paths in cats.items():
    if paths:
        print(f"=== {cat.upper()} ({len(paths)}) ===")
        for p in paths:
            print(f"  {p}")
        print()

with open("endpoints_bundle.json", "w", encoding="utf-8") as f:
    json.dump({"total": len(all_paths),
               "by_category": cats,
               "all": sorted(all_paths)}, f, ensure_ascii=False, indent=2)
print("✅ Salvo em endpoints_bundle.json")

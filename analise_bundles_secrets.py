"""Procura secrets, IPs internos, URLs hardcoded nos bundles JS."""
import re, os, glob, json
from collections import defaultdict

patterns = {
    "AWS Access Key":   re.compile(r"AKIA[0-9A-Z]{16}"),
    "Google API Key":   re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "Bearer JWT":       re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "RSA Private":      re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "Telegram Bot":     re.compile(r"\b\d{9,10}:AA[A-Za-z0-9_-]{33}\b"),
    "Stripe Key":       re.compile(r"sk_(?:test|live)_[A-Za-z0-9]{24,}"),
    # IP RFC1918
    "Internal IP RFC1918":
        re.compile(r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+\b"),
    # IP suspeito no range vazado pelo backend
    "Internal IP 192.10":
        re.compile(r"\b192\.10\.\d+\.\d+\b"),
    # localhost
    "localhost URL":
        re.compile(r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)[\w./:?&=%-]*"),
    # generic secret/key/password literal
    "Generic Secret literal":
        re.compile(r"""(?i)(secret|api[_-]?key|password|token|auth)\s*[:=]\s*["']([^"'\s]{16,})["']"""),
    # API endpoint hardcoded com porta interna
    "Internal port URL":
        re.compile(r"https?://[\w.-]+:(?:300\d|808\d|6379|27017|5432|3306|11211)[\w./:?&=%-]*"),
}

found = defaultdict(list)
for fp in glob.glob("bundles/*.js") + glob.glob("bundles/*.json"):
    try:
        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        continue
    fname = os.path.basename(fp)
    for name, pat in patterns.items():
        for m in pat.finditer(content):
            match = m.group(0)
            # Pega contexto (50 chars antes/depois)
            start = max(0, m.start() - 30)
            end   = min(len(content), m.end() + 30)
            ctx   = content[start:end].replace("\n", " ")
            found[name].append({
                "file": fname,
                "match": match[:100],
                "context": ctx[:200],
            })

# Imprime resumo
for name in patterns:
    hits = found.get(name, [])
    if not hits:
        continue
    print("=" * 60)
    print(f"{name} — {len(hits)} matches")
    print("=" * 60)
    seen = set()
    unique = []
    for h in hits:
        k = h["match"]
        if k in seen:
            continue
        seen.add(k)
        unique.append(h)
    print(f"  ({len(unique)} únicos)\n")
    for h in unique[:15]:
        print(f"  {h['file']}: {h['match']}")
        print(f"    ctx: ...{h['context']}...\n")

# Salva JSON
with open("analise_bundles_secrets.json","w",encoding="utf-8") as f:
    json.dump({k: list({h["match"]: h for h in v}.values())
               for k,v in found.items()},
              f, ensure_ascii=False, indent=2, default=str)
print("\n✅ Saída em analise_bundles_secrets.json")

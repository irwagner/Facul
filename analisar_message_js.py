"""
Análise completa do message.js (3.7MB protobuf schema).
Extrai:
  1. Todos os tipos de mensagem (enums)
  2. Todas as mensagens (classes protobuf) com seus campos
  3. Schema completo de PlayerLoginReq e mensagens de auth
  4. Campos que contêm 'token', 'auth', 'player', 'balance'
  5. Mapa de game IDs
  6. Mensagens que fazem parte do fluxo de login/auth
"""
import re, json

with open("bundles/ds.amizade777.com_message.js", "r", encoding="utf-8", errors="ignore") as f:
    content = f.read()

print(f"Tamanho: {len(content):,} chars")

# ─── 1. Todos os enums ────────────────────────────────────────

print("\n" + "=" * 60)
print("1. ENUMS COMPLETOS")
print("=" * 60)

# Padrão: values[valuesById[N] = "NAME"] = N
enum_entries = re.findall(r'valuesById\[(\d+)\]\s*=\s*["\']([A-Z_a-z0-9]+)["\']', content)
enums_by_val = {}
for val, name in enum_entries:
    enums_by_val[int(val)] = name

# Agrupar: qual enum group pertence (procura o contexto)
# Por enquanto imprime por valor
print(f"\n  Total de entradas de enum: {len(enums_by_val)}")

# Separar por range (convenção: 0-99 = sistema, 100-299 = player, 1000+ = game)
groups = {
    "sistema (0-99)":      [(v,n) for v,n in sorted(enums_by_val.items()) if v < 100],
    "player (100-299)":    [(v,n) for v,n in sorted(enums_by_val.items()) if 100 <= v < 300],
    "game (300-999)":      [(v,n) for v,n in sorted(enums_by_val.items()) if 300 <= v < 1000],
    "game_id (1000+)":     [(v,n) for v,n in sorted(enums_by_val.items()) if v >= 1000],
}
for group_name, items in groups.items():
    if items:
        print(f"\n  --- {group_name} ({len(items)}) ---")
        for v, n in items[:60]:
            print(f"    {v:6d} = {n}")
        if len(items) > 60:
            print(f"    ... e mais {len(items)-60}")

# ─── 2. Classes/Mensagens protobuf com campos ─────────────────

print("\n" + "=" * 60)
print("2. MENSAGENS PROTOBUF — CAMPOS")
print("=" * 60)

# Padrão de definição de mensagem protobuf em JS:
# MessageName.prototype.xxx = $util.Long...  OU
# MessageName.fields = {...}  OU
# MessageName.encode = function(m, w) {...}

# Buscar .encode com campos explícitos
# Ex: if (m.token != null ...) w.uint32(10).string(m.token)
encode_blocks = re.finditer(
    r'(\w+)\.encode\s*=\s*(?:function|(?:[\w$]+)\s*=\s*(?:function)?)\s*\([^)]*\)\s*\{([^}]{20,2000})\}',
    content
)

message_fields = {}
for match in encode_blocks:
    msg_name = match.group(1)
    body = match.group(2)
    # Extrair campos: w.uint32(tag).type(m.fieldName)
    fields = re.findall(r'm\.([a-zA-Z_][a-zA-Z0-9_]*)\b', body)
    fields = [f for f in fields if f not in ('token','constructor','encode','decode',
                                               'verify','create','fromObject',
                                               'toObject','toJSON')]
    if fields and msg_name not in ('module', 'exports', 'Object', 'Array'):
        message_fields[msg_name] = list(dict.fromkeys(fields))  # dedup preservando ordem

print(f"  {len(message_fields)} mensagens com campos extraídos")

# Mostrar mensagens mais relevantes
priority_msgs = []
for name, fields in message_fields.items():
    score = 0
    name_lower = name.lower()
    if any(k in name_lower for k in ('login','auth','player','connect','token','req','reply','request','response')):
        score += 10
    if any(k in name_lower for k in ('balance','pay','recharge','withdraw','game','lobby')):
        score += 5
    priority_msgs.append((score, name, fields))

priority_msgs.sort(reverse=True)
for score, name, fields in priority_msgs[:40]:
    print(f"\n  [{score}] {name}")
    print(f"    campos: {fields}")

# ─── 3. Foco em PlayerLoginReq ────────────────────────────────

print("\n" + "=" * 60)
print("3. PLAYER LOGIN REQ — SCHEMA COMPLETO")
print("=" * 60)

# Buscar PlayerLoginReq ou qualquer coisa parecida
for pattern in [r'PlayerLoginReq', r'LoginReq', r'AuthReq', r'ConnectReq', r'loginReq']:
    hits = list(re.finditer(pattern, content, re.I))
    if hits:
        print(f"\n  Pattern {pattern!r}: {len(hits)} ocorrências")
        for hit in hits[:5]:
            start = max(0, hit.start() - 100)
            end   = min(len(content), hit.end() + 300)
            print(f"  pos {hit.start()}:")
            print(f"    {content[start:end]!r}")

# ─── 4. Buscar fluxo de auth no WS ──────────────────────────

print("\n" + "=" * 60)
print("4. FLUXO DE AUTH NO WS")
print("=" * 60)

# Buscar onde msgtype=10 é usado e o que é construído
for pattern in [
    r'msgtype.*?10',
    r'SERVER_AUTH',
    r'\.token\s*=',
    r'PLAYER_LOGIN_REQ',
]:
    hits = list(re.finditer(pattern, content, re.I))
    if hits:
        print(f"\n  {pattern!r}: {len(hits)} ocorrências")
        seen = set()
        for hit in hits[:3]:
            ctx = content[max(0,hit.start()-150):hit.end()+150]
            key = ctx[:60]
            if key not in seen:
                seen.add(key)
                print(f"    ...{ctx}...")

# ─── 5. Game IDs completos ───────────────────────────────────

print("\n" + "=" * 60)
print("5. GAME IDs (GID_*)")
print("=" * 60)

gids = re.findall(r'GID_([A-Z0-9_]+)\s*\]\s*=\s*(\d+)', content)
print(f"  Total GIDs: {len(gids)}")
# Organizar por categoria
gid_dict = {name: int(val) for name, val in gids}
categories = {}
for name, val in gid_dict.items():
    cat = name.split("_")[0] if "_" in name else "OTHER"
    categories.setdefault(cat, []).append((val, name))
for cat, items in sorted(categories.items()):
    print(f"\n  {cat} ({len(items)} games):")
    for val, name in sorted(items)[:10]:
        print(f"    {val:6d} = {name}")
    if len(items) > 10:
        print(f"    ... +{len(items)-10}")

# ─── 6. Estrutura do frame de login ──────────────────────────

print("\n" + "=" * 60)
print("6. CONSTRUÇÃO DO FRAME DE LOGIN NO JS DO APP")
print("=" * 60)

# Buscar no bundle do app (não message.js) como o WS é usado
app_bundles = []
import glob, os
for fp in glob.glob("bundles/ds.amizade777.com_index*.js"):
    app_bundles.append(fp)
for fp in glob.glob("bundles/m.amizade777.com_index*.js"):
    app_bundles.append(fp)

for fp in app_bundles:
    try:
        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
            app_content = f.read()
    except: continue

    # Buscar onde websocket é conectado e como o login é enviado
    ws_connects = re.finditer(r'websocket|WebSocket|wss://', app_content, re.I)
    contexts = set()
    for m in ws_connects:
        ctx = app_content[max(0,m.start()-200):m.end()+400]
        key = ctx[:80]
        if key not in contexts:
            contexts.add(key)
            print(f"  [{os.path.basename(fp)}] pos {m.start()}:")
            print(f"    {ctx[:400]!r}")
            print()

    # Buscar envio de msgtype
    for pattern in [r'msgtype.*?10', r'SERVER_AUTH', r'protobuf.*?login', r'socket.*?send']:
        for m in re.finditer(pattern, app_content, re.I):
            ctx = app_content[max(0,m.start()-100):m.end()+200]
            print(f"  {pattern!r}: {ctx[:250]!r}")
            print()
            break

# ─── 7. Salvar resultado em JSON ──────────────────────────────

result = {
    "total_enum_entries": len(enums_by_val),
    "enums_by_value": {str(k): v for k,v in enums_by_val.items()},
    "message_fields": message_fields,
    "game_ids": {k: v for k,v in gid_dict.items()},
    "total_game_ids": len(gid_dict),
}

with open("message_js_analysis.json", "w", encoding="utf-8") as f:
    json.dump(result, f, ensure_ascii=False, indent=2)
print(f"\n✅ Análise salva em message_js_analysis.json")

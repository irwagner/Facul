"""
Extrai o schema completo do PlayerLoginReq e o fluxo de
autenticação do WebSocket a partir do message.js.
"""
import re, json, base64, struct

with open("bundles/ds.amizade777.com_message.js", "r", encoding="utf-8", errors="ignore") as f:
    content = f.read()

# ─── Encontrar o bloco completo do PlayerLoginReq ─────────────

print("=" * 60)
print("PlayerLoginReq — BLOCO COMPLETO")
print("=" * 60)

# Localizar início
start_idx = content.find("base.PlayerLoginReq = (function")
if start_idx == -1:
    start_idx = content.find("PlayerLoginReq = (function")

if start_idx == -1:
    print("Não encontrado!")
else:
    # Pegar 3000 chars depois (a definição completa)
    block = content[start_idx:start_idx+3000]
    print(block)

# ─── Encontrar PlayerLoginReply ────────────────────────────────

print("\n" + "=" * 60)
print("PlayerLoginReply — BLOCO COMPLETO")
print("=" * 60)

start_idx2 = content.find("base.PlayerLoginReply = (function")
if start_idx2 == -1:
    start_idx2 = content.find("PlayerLoginReply = (function")
if start_idx2 != -1:
    print(content[start_idx2:start_idx2+2000])

# ─── Encontrar o envelope (frame wrapper) ─────────────────────

print("\n" + "=" * 60)
print("FRAME ENVELOPE — MsgWrapper ou similar")
print("=" * 60)

for name in ["MsgWrapper", "Wrapper", "Frame", "Envelope", "BaseMsg", "Packet"]:
    idx = content.find(f"base.{name} = (function")
    if idx == -1:
        idx = content.find(f"{name} = (function")
    if idx != -1:
        print(f"\n  [{name}] encontrado:")
        print(content[idx:idx+1500])
        break

# ─── Encontrar a classe WS_CMD ou CMD_TYPE ────────────────────

print("\n" + "=" * 60)
print("CMD ENUM (tipo de mensagem no frame)")
print("=" * 60)

for name in ["WS_CMD", "CMD_TYPE", "CmdType", "MsgType", "MSG_CMD"]:
    idx = content.find(name)
    if idx != -1:
        print(f"\n  [{name}]:")
        print(content[max(0,idx-50):idx+500])
        break

# ─── Análise do encode de PlayerLoginReq ─────────────────────

print("\n" + "=" * 60)
print("ENCODE DE PlayerLoginReq")
print("=" * 60)

# O encode vai mostrar exatamente quais campos e tags usar
encode_start = content.find("PlayerLoginReq.encode")
if encode_start != -1:
    print(content[encode_start:encode_start+1000])

# ─── Formato do frame de transporte ──────────────────────────

print("\n" + "=" * 60)
print("FORMATO DO FRAME — como encapsular a mensagem")
print("=" * 60)

# Buscar onde o WS envia dados: provavelmente usa um wrapper
# com campos: cmd(int), data(bytes)
for pattern in [
    r'\.send\(.*?protobuf',
    r'\.encode.*?\.finish\(\)',
    r'cmd.*?data.*?encode',
    r'msgtype.*?msg.*?protobuf',
]:
    for m in re.finditer(pattern, content[:50000], re.I | re.DOTALL):
        ctx = content[max(0,m.start()-100):m.end()+200]
        print(f"  [{pattern!r}]:")
        print(f"  {ctx[:400]!r}")
        print()
        break

# ─── Construir o payload correto ─────────────────────────────

print("\n" + "=" * 60)
print("RECONSTRUÇÃO DO PAYLOAD CORRETO")
print("=" * 60)

# Com base no JSDoc:
# PlayerLoginReq.token = string (field 1)
# O frame JSON que vimos tem: {"msgtype": N, "msg": base64(protobuf)}
# msgtype = 100 (PLAYER_LOGIN_REQ)
# msg = protobuf(PlayerLoginReq{token: "..."})

def encode_protobuf_string(field, value):
    """field:LEN type com string value"""
    tag = (field << 3) | 2
    b = value.encode() if isinstance(value, str) else value

    def varint(v):
        out = b""
        while v > 0x7F:
            out += bytes([(v & 0x7F) | 0x80]); v >>= 7
        return out + bytes([v & 0x7F])

    return varint(tag) + varint(len(b)) + b

# Construir frame de login com token anão
token_anao = "137027"
proto = encode_protobuf_string(1, token_anao)
msg_b64 = base64.b64encode(proto).decode()
frame_anao = json.dumps({"msgtype": 100, "msg": msg_b64, "errcode": None})
print(f"Frame com token anão (uid=137027):")
print(f"  {frame_anao}")
print(f"  protobuf hex: {proto.hex()}")

# Token real (exemplo)
token_real = "137027:1781044962:3001:3e62fbd68149bfbfbfd3470b81ce2701"
proto_real = encode_protobuf_string(1, token_real)
msg_b64_real = base64.b64encode(proto_real).decode()
frame_real = json.dumps({"msgtype": 100, "msg": msg_b64_real, "errcode": None})
print(f"\nFrame com token real:")
print(f"  {frame_real}")
print(f"  protobuf hex: {proto_real.hex()}")

# ─── Verificar o que SYNC_ONLINE_STATUS retorna ──────────────

print("\n" + "=" * 60)
print("SyncOnlineStatus — campos")
print("=" * 60)

sync_idx = content.find("SyncOnlineStatus")
if sync_idx == -1:
    sync_idx = content.find("SYNC_ONLINE_STATUS")
if sync_idx != -1:
    # Pegar a definição da mensagem
    # Procura "base.SyncOnlineStatus = (function"
    for search_name in ["SyncOnlineStatus", "OnlineStatus"]:
        idx = content.find(f"base.{search_name} = (function")
        if idx != -1:
            print(content[idx:idx+1500])
            break

# ─── Analisar o app bundle pra ver como WS é usado ───────────

print("\n" + "=" * 60)
print("APP BUNDLE — uso do WS e PlayerLoginReq")
print("=" * 60)

import glob
for fp in glob.glob("bundles/ds.amizade777.com_index*.js"):
    try:
        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
            app = f.read()
    except: continue

    # Busca por PlayerLoginReq no app bundle
    for pattern in ["PlayerLoginReq", "PLAYER_LOGIN_REQ", "msgtype.*100", "WsClient", "websocket.*token"]:
        for m in re.finditer(pattern, app, re.I):
            ctx = app[max(0,m.start()-200):m.end()+400]
            if "token" in ctx.lower() or "protobuf" in ctx.lower():
                print(f"  [{pattern!r}] pos {m.start()}:")
                print(f"  {ctx[:500]!r}")
                print()
                break

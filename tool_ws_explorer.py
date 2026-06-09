"""
tool_ws_explorer.py
===================
Exploração completa do WebSocket com:
  A. Engenharia reversa do protobuf (parse do message.js)
  B. Tentativa de auth com token anão
  C. Tentativa de auth com token válido
  D. Enumeração de game IDs e salas
  E. Verificação se dados de outros players vazam no WS
"""
import ssl, socket, base64, struct, json, time, re, hashlib
import urllib.request, urllib.error
from datetime import datetime, timezone

ctx = ssl.create_default_context()
ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
BASE = "https://ds.amizade777.com"
HOST = "ds.amizade777.com"
WS_PATH = "/websocket6"

RESULTS = []

# ─── Protobuf helpers ─────────────────────────────────────────

def encode_varint(v):
    out = b""
    while v > 0x7F:
        out += bytes([(v & 0x7F) | 0x80]); v >>= 7
    return out + bytes([v & 0x7F])

def encode_field_string(field, value):
    tag = (field << 3) | 2
    b = value.encode() if isinstance(value, str) else value
    return encode_varint(tag) + encode_varint(len(b)) + b

def encode_field_int(field, value):
    tag = (field << 3) | 0
    return encode_varint(tag) + encode_varint(value)

def decode_varint(data, pos):
    v = 0; shift = 0
    while pos < len(data):
        b = data[pos]; pos += 1
        v |= (b & 0x7F) << shift
        if not (b & 0x80): break
        shift += 7
    return v, pos

def decode_protobuf(data):
    """Decodifica protobuf em dict {field: value}."""
    fields = {}
    pos = 0
    while pos < len(data):
        try:
            tag, pos = decode_varint(data, pos)
            field = tag >> 3
            wire  = tag & 0x07
            if wire == 0:  # varint
                val, pos = decode_varint(data, pos)
                fields[field] = val
            elif wire == 2:  # length-delimited
                length, pos = decode_varint(data, pos)
                val = data[pos:pos+length]; pos += length
                try: fields[field] = val.decode("utf-8","ignore")
                except: fields[field] = val.hex()
            elif wire == 5:  # 32-bit
                fields[field] = struct.unpack("<I", data[pos:pos+4])[0]; pos += 4
            elif wire == 1:  # 64-bit
                fields[field] = struct.unpack("<Q", data[pos:pos+8])[0]; pos += 8
            else:
                break
        except Exception:
            break
    return fields

# ─── WS helpers ───────────────────────────────────────────────

def ws_connect(host, path, token=None):
    key = base64.b64encode(b"kiro_ws_tool_2026").decode()
    hdrs = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n"
            f"Origin: https://{host}\r\nUser-Agent: Mozilla/5.0\r\n")
    if token: hdrs += f"Token: {token}\r\n"
    hdrs += "\r\n"
    try:
        raw = socket.create_connection((host, 443), timeout=10)
        ssl_s = ctx.wrap_socket(raw, server_hostname=host)
        ssl_s.send(hdrs.encode())
        resp = ssl_s.recv(4096).decode("utf-8","ignore")
        return ssl_s, resp
    except Exception as ex:
        return None, str(ex)

def ws_send_json(sock, obj):
    payload = json.dumps(obj, ensure_ascii=False).encode()
    mask = b'\x4b\x1a\x7c\x3e'
    hdr = bytearray([0x81])
    if len(payload) < 126:
        hdr.append(0x80 | len(payload))
    else:
        hdr.append(0xFE); hdr += struct.pack(">H", len(payload))
    hdr += mask
    masked = bytearray(p ^ mask[i%4] for i,p in enumerate(payload))
    sock.send(bytes(hdr) + bytes(masked))

def ws_recv_frame(sock, timeout=3):
    sock.settimeout(timeout)
    try:
        hdr = b""
        while len(hdr) < 2:
            c = sock.recv(2-len(hdr))
            if not c: return None
            hdr += c
        op = hdr[0] & 0x0F
        masked = bool(hdr[1] & 0x80)
        ln = hdr[1] & 0x7F
        if ln == 126: ln = struct.unpack(">H", sock.recv(2))[0]
        elif ln == 127: ln = struct.unpack(">Q", sock.recv(8))[0]
        if masked: mkey = sock.recv(4)
        data = b""
        rem = min(ln, 65536)
        while rem > 0:
            c = sock.recv(rem); 
            if not c: break
            data += c; rem -= len(c)
        if masked:
            data = bytes(b ^ mkey[i%4] for i,b in enumerate(data))
        return {"op": op, "data": data}
    except socket.timeout:
        return None
    except Exception:
        return None

def collect_frames(sock, duration=4):
    frames = []
    end = time.time() + duration
    while time.time() < end:
        f = ws_recv_frame(sock, 1)
        if f: frames.append(f)
    return frames

def parse_ws_frame(frame):
    try:
        j = json.loads(frame["data"].decode("utf-8","ignore"))
        mt = j.get("msgtype"); msg_b64 = j.get("msg",""); ec = j.get("errcode")
        payload = {}
        if msg_b64:
            try:
                raw = base64.b64decode(msg_b64)
                payload = decode_protobuf(raw)
            except: pass
        return {"json": j, "msgtype": mt, "errcode": ec, "payload": payload}
    except:
        return {"raw_hex": frame["data"][:32].hex(), "op": frame["op"]}

def login():
    pl = {"appChannel":"pc","appPackageName":"com.slots.big",
          "deviceId":"0beb614f-8838-43ef-00fc-0029f7d5d20f",
          "deviceModel":"WEB","deviceVersion":"WEB","appVersion":"1.0.0",
          "sysTimezone":None,"sysLanguage":None,"phone":"21998498419","password":"21998498419"}
    h = {"User-Agent":"Mozilla/5.0","Content-Type":"application/json"}
    r = urllib.request.Request(BASE+"/prod-api/player/sign-in",
                               data=json.dumps(pl).encode(), headers=h, method="POST")
    with urllib.request.urlopen(r, timeout=10, context=ctx) as resp:
        b = json.loads(resp.read())
        if b.get("code") != 200: raise RuntimeError(str(b))
        return b["data"]["token"]

# ─── Extrair schema do message.js ────────────────────────────

print("=" * 60)
print("A. PARSE DO PROTOBUF SCHEMA (message.js)")
print("=" * 60)

msg_js = None
for fp in ["bundles/ds.amizade777.com_message.js",
           "bundles/m.amizade777.com_message.js"]:
    try:
        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
            msg_js = f.read(200000)
        print(f"  Lido: {fp} ({len(msg_js):,} chars)")
        break
    except: pass

if msg_js:
    # Extrair todos os @property {type} NAME=VALUE do JSDoc
    props = re.findall(r'@property\s*\{(\w+)\}\s+([A-Z_]+)\s*=\s*(\d+)', msg_js)
    cmd_types = [(n, int(v)) for t,n,v in props]
    print(f"\n  Tipos de mensagem ({len(cmd_types)}):")
    for name, val in sorted(cmd_types, key=lambda x: x[1])[:50]:
        print(f"    {val:4d} = {name}")

    # Extrair campos de cada mensagem
    print("\n  Mensagens com campo 'token':")
    token_msgs = re.findall(r'(\w+)\s*=\s*function[^{]*\{[^}]*token[^}]*\}', msg_js[:50000], re.I)
    for m in token_msgs[:10]: print(f"    {m}")

    # Buscar LoginReq ou AuthReq
    login_ctx = re.findall(r'.{0,200}(?:LoginReq|AuthReq|ConnectReq|authToken)[^{;]*', msg_js[:100000], re.I)
    print(f"\n  Contextos de LoginReq/AuthReq:")
    seen = set()
    for lc in login_ctx[:10]:
        k = lc[:40]
        if k not in seen:
            seen.add(k); print(f"    {lc[:200]!r}")

# ─── B. WS sem token — observação detalhada ─────────────────

print("\n" + "=" * 60)
print("B. WS SEM TOKEN — FRAMES COMPLETOS")
print("=" * 60)

sock, resp = ws_connect(HOST, WS_PATH)
if sock and "101" in resp:
    print("  ✅ Conectado sem token")
    frames = collect_frames(sock, 6)
    print(f"  {len(frames)} frames em 6 segundos:")
    for f in frames:
        parsed = parse_ws_frame(f)
        mt = parsed.get("msgtype"); pl = parsed.get("payload",{})
        print(f"    msgtype={mt} payload={pl}")
        if pl:
            # Se tiver campos com valores interessantes
            for k, v in pl.items():
                if isinstance(v, (int, float)) and v > 1700000000000:
                    print(f"      field {k} = {v} (timestamp ms?)")
    sock.close()
else:
    print(f"  ❌ Não conectou: {resp[:100]}")

# ─── C. WS com vários formatos de SERVER_AUTH ────────────────

print("\n" + "=" * 60)
print("C. SERVER_AUTH (msgtype=10) — MÚLTIPLOS FORMATOS")
print("=" * 60)

def test_server_auth(token_str, label):
    """Testa SERVER_AUTH com diferentes encodings do token."""
    sock, resp = ws_connect(HOST, WS_PATH)
    if not sock or "101" not in resp:
        print(f"  [{label}] Não conectou")
        return None

    # Receber heartbeat inicial
    ws_recv_frame(sock, 2)

    auth_variants = [
        # Formato 1: token como string no field 1
        ("field1_string", encode_field_string(1, token_str)),
        # Formato 2: token no field 2
        ("field2_string", encode_field_string(2, token_str)),
        # Formato 3: só os campos numéricos (uid no field 1, ts no field 2)
        ("uid_ts_port", (encode_field_int(1, int(token_str.split(":")[0]) if ":" in token_str else int(token_str)) +
                         encode_field_int(2, int(token_str.split(":")[1]) if ":" in token_str and len(token_str.split(":"))>1 else 0) +
                         encode_field_int(3, 3001))),
        # Formato 4: token completo como string no field 3
        ("field3_string", encode_field_string(3, token_str)),
    ]

    result = None
    for variant_name, proto_payload in auth_variants:
        msg_b64 = base64.b64encode(proto_payload).decode()
        ws_send_json(sock, {"msgtype": 10, "msg": msg_b64, "errcode": None})
        time.sleep(0.5)
        frames = []
        for _ in range(5):
            f = ws_recv_frame(sock, 1)
            if f: frames.append(parse_ws_frame(f))
        for parsed in frames:
            mt = parsed.get("msgtype"); ec = parsed.get("errcode")
            pl = parsed.get("payload",{})
            if mt not in (1, 3, 4):  # não é só heartbeat
                print(f"  [{label}/{variant_name}] msgtype={mt} errcode={ec} payload={pl}")
                if mt == 11:  # SYNC_ONLINE_STATUS = autenticado!
                    print(f"  🔴 AUTENTICADO! msgtype=11")
                    result = {"authenticated": True, "token": token_str,
                              "variant": variant_name, "payload": pl}
                    RESULTS.append(result)
                elif mt == 2:  # UNLOGIN
                    pass  # normal
                elif ec == 100:  # TOKEN_INVALID
                    pass
                else:
                    RESULTS.append({"msgtype": mt, "ec": ec, "label": label,
                                    "variant": variant_name, "payload": pl})
    sock.close()
    return result

# Testar com token anão uid=137027
print("\n  Token anão uid=137027:")
r1 = test_server_auth("137027", "anao_137027")

print("\n  Token anão uid=1:")
r2 = test_server_auth("1", "anao_1")

# Testar com token válido
print("\n  Token válido:")
try:
    valid_tok = login()
    r3 = test_server_auth(valid_tok, "valido")
except Exception as ex:
    print(f"  [login falhou: {ex}]")
    r3 = None

# ─── D. WS sem auth — tentar comandos de leitura ─────────────

print("\n" + "=" * 60)
print("D. WS COMANDOS SEM AUTH (game list, online players)")
print("=" * 60)

sock, resp = ws_connect(HOST, WS_PATH)
if sock and "101" in resp:
    ws_recv_frame(sock, 1)  # heartbeat

    # Tentar SEND_COMMAND (6) com payloads que pedem lista de jogos
    commands_to_try = [
        ("get_game_list",     encode_field_int(1, 6)),    # cmd=6
        ("get_online",        encode_field_int(1, 11)),   # cmd=11
        ("get_lobby",         encode_field_int(1, 1)),    # cmd=1
        ("sync_status",       encode_field_int(1, 100)),  # cmd=100
    ]
    for cmd_name, proto_payload in commands_to_try:
        msg_b64 = base64.b64encode(proto_payload).decode()
        ws_send_json(sock, {"msgtype": 6, "msg": msg_b64, "errcode": None})
        time.sleep(0.3)
        f = ws_recv_frame(sock, 1)
        if f:
            parsed = parse_ws_frame(f)
            mt = parsed.get("msgtype"); ec = parsed.get("errcode")
            if mt not in (1, None):
                print(f"  [{cmd_name}] msgtype={mt} errcode={ec} payload={parsed.get('payload')}")
    sock.close()

# ─── E. WS SYNC_ONLINE_STATUS — vaza players online? ──────────

print("\n" + "=" * 60)
print("E. WS SYNC_ONLINE_STATUS (msgtype=11) vaza info?")
print("=" * 60)

# Se o WS envia msgtype=11 automaticamente, pode conter uid de outros players
sock, resp = ws_connect(HOST, WS_PATH)
if sock and "101" in resp:
    print("  Conectado. Aguardando msgtype=11 por 10 segundos...")
    frames = collect_frames(sock, 10)
    for f in frames:
        parsed = parse_ws_frame(f)
        if parsed.get("msgtype") == 11:
            print(f"  🟡 SYNC_ONLINE_STATUS recebido! payload={parsed.get('payload')}")
            RESULTS.append({"type":"sync_online","payload":parsed.get("payload")})
        elif parsed.get("msgtype") not in (1, 3, 4):
            print(f"  Msgtype={parsed.get('msgtype')} payload={parsed.get('payload')}")
    sock.close()

# ─── Salvar ───────────────────────────────────────────────────

with open("ws_explorer_resultados.json","w",encoding="utf-8") as f:
    json.dump(RESULTS, f, ensure_ascii=False, indent=2, default=str)

auth_ok = [r for r in RESULTS if r.get("authenticated")]
print(f"\n{'='*60}")
print(f"WS Explorer: {len(RESULTS)} eventos | {len(auth_ok)} auth bem-sucedidos")
if auth_ok:
    for r in auth_ok:
        print(f"  🔴 AUTH: {r}")
else:
    print("  Nenhum auth via WS confirmado.")
print(f"\n✅ ws_explorer_resultados.json")

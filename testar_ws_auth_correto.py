"""
Testa autenticação WebSocket com o schema correto.

Schema confirmado pelo message.js:
  - PLAYER_LOGIN_REQ = msgtype 100
  - PlayerLoginReq = { field1 (string): token }
  - O frame JSON = {"msgtype": 100, "msg": base64(protobuf), "errcode": null}

Testa:
  1. Token válido (via login HTTP primeiro)
  2. Token anão uid=137027 (só o número)
  3. Token anão uid=1
  4. Verifica o PlayerLoginReply (msgtype=101) e os dados retornados
"""
import ssl, socket, base64, struct, json, time
import urllib.request, urllib.error
from datetime import datetime

ctx = ssl.create_default_context()
ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
HOST = "ds.amizade777.com"
WS_PATH = "/websocket6"
BASE = "https://ds.amizade777.com"

# ─── Protobuf helpers ─────────────────────────────────────────

def encode_varint(v):
    out = b""
    while v > 0x7F:
        out += bytes([(v & 0x7F) | 0x80]); v >>= 7
    return out + bytes([v & 0x7F])

def encode_string_field(field_num, value):
    """Encoda field wireType=2 (LEN) com string."""
    tag = (field_num << 3) | 2
    b = value.encode("utf-8") if isinstance(value, str) else value
    return encode_varint(tag) + encode_varint(len(b)) + b

def decode_varint(data, pos):
    v = 0; shift = 0
    while pos < len(data):
        b = data[pos]; pos += 1
        v |= (b & 0x7F) << shift
        if not (b & 0x80): break
        shift += 7
    return v, pos

def decode_proto(data):
    """Decodifica protobuf básico."""
    result = {}; pos = 0
    while pos < len(data):
        try:
            tag_val, pos = decode_varint(data, pos)
            field = tag_val >> 3; wire = tag_val & 7
            if wire == 0:
                val, pos = decode_varint(data, pos)
                result.setdefault(field, []).append(val)
            elif wire == 2:
                ln, pos = decode_varint(data, pos)
                raw = data[pos:pos+ln]; pos += ln
                try: result.setdefault(field, []).append(raw.decode("utf-8","ignore"))
                except: result.setdefault(field, []).append(raw.hex())
            elif wire == 5: pos += 4
            elif wire == 1: pos += 8
            else: break
        except: break
    return result

# ─── WS helpers ────────────────────────────────────────────────

def ws_connect(host, path):
    key = base64.b64encode(b"ws_auth_test_2026!").decode()
    hdrs = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n"
            f"Origin: https://{host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
    raw = socket.create_connection((host, 443), timeout=10)
    ssl_s = ctx.wrap_socket(raw, server_hostname=host)
    ssl_s.send(hdrs.encode())
    resp = ssl_s.recv(4096).decode("utf-8","ignore")
    return ssl_s if "101" in resp else None

def ws_send(sock, obj):
    payload = json.dumps(obj, ensure_ascii=False).encode()
    mask = b'\x42\x13\x71\x9a'
    hdr = bytearray([0x81])
    if len(payload) < 126: hdr.append(0x80 | len(payload))
    else:
        hdr.append(0xFE); hdr += struct.pack(">H", len(payload))
    hdr += mask
    masked = bytearray(p ^ mask[i%4] for i,p in enumerate(payload))
    sock.send(bytes(hdr) + bytes(masked))

def ws_recv(sock, timeout=5):
    sock.settimeout(timeout)
    try:
        hdr = b""
        while len(hdr) < 2:
            c = sock.recv(2-len(hdr));
            if not c: return None
            hdr += c
        op = hdr[0] & 0xF; masked = bool(hdr[1] & 0x80); ln = hdr[1] & 0x7F
        if ln == 126: ln = struct.unpack(">H", sock.recv(2))[0]
        elif ln == 127: ln = struct.unpack(">Q", sock.recv(8))[0]
        if masked: mk = sock.recv(4)
        data = b""
        while len(data) < min(ln, 65536):
            c = sock.recv(min(ln, 65536) - len(data))
            if not c: break
            data += c
        if masked: data = bytes(b ^ mk[i%4] for i,b in enumerate(data))
        return {"op": op, "data": data}
    except socket.timeout: return None
    except: return None

def parse_frame(f):
    try:
        j = json.loads(f["data"].decode("utf-8","ignore"))
        mt = j.get("msgtype"); msg_b64 = j.get("msg",""); ec = j.get("errcode")
        pl = {}
        if msg_b64:
            try:
                raw = base64.b64decode(msg_b64)
                pl = decode_proto(raw)
            except: pass
        return mt, ec, pl, j
    except:
        return None, None, {}, {}

def recv_all(sock, duration=5):
    frames = []
    end = time.time() + duration
    while time.time() < end:
        f = ws_recv(sock, 1)
        if f: frames.append(parse_frame(f))
    return frames

def login_http():
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

# ─── Teste 1: Token válido via msgtype=100 ────────────────────

print("=" * 60)
print("TESTE 1 — Token válido + PLAYER_LOGIN_REQ (msgtype=100)")
print("=" * 60)

try:
    valid_token = login_http()
    print(f"Token: {valid_token}")

    sock = ws_connect(HOST, WS_PATH)
    if not sock:
        print("Não conectou!")
    else:
        # Receber heartbeat inicial
        f = ws_recv(sock, 2)
        if f:
            mt, ec, pl, _ = parse_frame(f)
            print(f"  Heartbeat inicial: msgtype={mt} payload={pl}")

        # Enviar PLAYER_LOGIN_REQ (msgtype=100) com token real
        proto = encode_string_field(1, valid_token)
        msg_b64 = base64.b64encode(proto).decode()
        login_frame = {"msgtype": 100, "msg": msg_b64, "errcode": None}
        print(f"\n  Enviando msgtype=100 com token real...")
        print(f"  proto hex: {proto.hex()}")
        ws_send(sock, login_frame)

        # Coletar resposta por 8 segundos
        print(f"  Aguardando resposta...")
        frames = recv_all(sock, 8)
        print(f"  {len(frames)} frames recebidos:")
        for mt, ec, pl, raw_j in frames:
            print(f"\n    msgtype={mt} errcode={ec}")
            print(f"    raw_json: {raw_j}")
            if pl:
                print(f"    proto_fields: {pl}")
                # Se é 101 (PlayerLoginReply), decodificar campos
                if mt == 101:
                    print(f"\n  🟢 PLAYER_LOGIN_REPLY RECEBIDO!")
                    print(f"  Campos: {pl}")
        sock.close()
except Exception as ex:
    print(f"  [ERRO]: {ex}")

# ─── Teste 2: Token anão uid=137027 ──────────────────────────

print("\n" + "=" * 60)
print("TESTE 2 — Token anão (uid=137027) + PLAYER_LOGIN_REQ")
print("=" * 60)

for token_str, label in [("137027", "anão uid=137027"), ("1", "anão uid=1")]:
    print(f"\n  Testando: {label} (Token={token_str!r})")
    sock = ws_connect(HOST, WS_PATH)
    if not sock:
        print("  Não conectou!")
        continue

    # Heartbeat
    ws_recv(sock, 1)

    proto = encode_string_field(1, token_str)
    msg_b64 = base64.b64encode(proto).decode()
    ws_send(sock, {"msgtype": 100, "msg": msg_b64, "errcode": None})

    frames = recv_all(sock, 6)
    for mt, ec, pl, raw_j in frames:
        if mt not in (1, 3, 4):
            print(f"  msgtype={mt} errcode={ec}")
            print(f"  raw: {raw_j}")
            if pl: print(f"  proto: {pl}")
            if mt == 101:
                print(f"  🔴 LOGIN VIA TOKEN ANÃO ACEITO! baseInfo={pl}")
            elif mt == 2:
                print(f"  UNLOGIN — rejeitado")
            elif ec == 100:
                print(f"  TOKEN_INVALID — rejeitado")
    sock.close()
    time.sleep(1)

# ─── Teste 3: Enviar PLAYER_BALANCE_REQ (109) após auth ───────

print("\n" + "=" * 60)
print("TESTE 3 — PLAYER_BALANCE_REQ (109) sem auth prévia")
print("=" * 60)

sock = ws_connect(HOST, WS_PATH)
if sock:
    ws_recv(sock, 1)
    # Enviar BALANCE_REQ sem auth
    ws_send(sock, {"msgtype": 109, "msg": "", "errcode": None})
    frames = recv_all(sock, 4)
    for mt, ec, pl, raw_j in frames:
        if mt not in (1,):
            print(f"  BALANCE_REQ sem auth: msgtype={mt} ec={ec} raw={raw_j}")
    sock.close()

# ─── Resumo ───────────────────────────────────────────────────

print(f"\n✅ Análise WS auth concluída em {datetime.now().isoformat()}")

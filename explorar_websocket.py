"""
Exploração do WebSocket aberto sem auth.

O WS usa protobuf JSON com campos:
  msgtype: número do comando
  msg: payload base64 (protobuf encodado)
  errcode: null ou código de erro

Comandos conhecidos do message.js:
  CONNECTED = 1
  UNLOGIN   = 2
  PING      = 3
  PONG      = 4
  CLOSE     = 5
  SEND_COMMAND = 6
  SERVER_AUTH  = 10
  SYNC_ONLINE_STATUS = 11
  PLAYER_LOGIN_REQ = 100 (do enum ERROR_CODE, pode ser cmd tbm)

Protocolo provável de autenticação:
  Cliente → SERVER_AUTH(10) com token no payload
  Servidor → responde com PLAYER_LOGIN_REQ ou erro TOKEN_INVALID(100)

Vamos tentar:
1. Conectar e observar o que vem sem auth
2. Enviar PONG (4) para ver se mantém conexão
3. Tentar SERVER_AUTH com token anão
4. Tentar SERVER_AUTH com token válido (para comparação)
"""
import ssl, socket, base64, struct, json, time, re, hashlib

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

HOST  = "ds.amizade777.com"
WS_PATH = "/websocket6"
BASE  = "https://ds.amizade777.com"

# ─── WebSocket raw helpers ───────────────────────────

def ws_connect(host, path, token=None):
    key = base64.b64encode(b"pentest_kiro_2026!").decode()
    headers = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Origin: https://{host}\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
    )
    if token:
        headers += f"Token: {token}\r\n"
    headers += "\r\n"

    raw = socket.create_connection((host, 443), timeout=10)
    ssl_sock = ctx.wrap_socket(raw, server_hostname=host)
    ssl_sock.send(headers.encode())
    resp = ssl_sock.recv(4096).decode("utf-8","ignore")
    return ssl_sock, resp

def ws_send(sock, message_str):
    """Envia frame WS texto com masking."""
    payload = message_str.encode("utf-8")
    mask = b'\x42\x13\x71\x9a'
    header = bytearray([0x81])  # FIN + TEXT
    if len(payload) < 126:
        header.append(0x80 | len(payload))
    elif len(payload) < 65536:
        header.append(0x80 | 126)
        header += struct.pack(">H", len(payload))
    else:
        header.append(0x80 | 127)
        header += struct.pack(">Q", len(payload))
    header += mask
    masked = bytearray(p ^ mask[i % 4] for i, p in enumerate(payload))
    sock.send(bytes(header) + bytes(masked))

def ws_recv(sock, timeout=3):
    """Recebe um frame WS."""
    sock.settimeout(timeout)
    try:
        header = b""
        while len(header) < 2:
            chunk = sock.recv(2 - len(header))
            if not chunk: return None
            header += chunk

        opcode = header[0] & 0x0F
        masked  = (header[1] & 0x80) != 0
        length  = header[1] & 0x7F

        if length == 126:
            length = struct.unpack(">H", sock.recv(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", sock.recv(8))[0]

        if masked:
            mask = sock.recv(4)

        data = b""
        remaining = min(length, 32768)
        while remaining > 0:
            chunk = sock.recv(remaining)
            if not chunk: break
            data += chunk
            remaining -= len(chunk)

        if masked:
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))

        return {"opcode": opcode, "data": data}
    except socket.timeout:
        return None
    except Exception:
        return None

def make_protobuf_varint(value):
    """Encode um inteiro como varint protobuf."""
    result = b""
    while value > 0x7F:
        result += bytes([(value & 0x7F) | 0x80])
        value >>= 7
    result += bytes([value & 0x7F])
    return result

def encode_protobuf_string(field_num, value):
    """Encoda field_num:LEN com string value."""
    tag = (field_num << 3) | 2
    encoded = value.encode("utf-8")
    return make_protobuf_varint(tag) + make_protobuf_varint(len(encoded)) + encoded

def encode_protobuf_int32(field_num, value):
    """Encoda field_num:VARINT com int value."""
    tag = (field_num << 3) | 0
    return make_protobuf_varint(tag) + make_protobuf_varint(value)

# ─── PARTE 1: Conectar e observar ──────────────────────────

print("=" * 60)
print("WS PARTE 1 — Conectar e observar (sem token)")
print("=" * 60)

sock, resp = ws_connect(HOST, WS_PATH)
if "101" in resp:
    print(f"  ✅ Conectado! {resp.split(chr(13))[0]}")
else:
    print(f"  ❌ Falhou: {resp[:100]}")
    exit()

# Coletar frames por 5 segundos
print("\n  Frames recebidos (5 segundos):")
start = time.time()
frames_raw = []
while time.time() - start < 5:
    frame = ws_recv(sock, timeout=1)
    if frame:
        frames_raw.append(frame)
        try:
            j = json.loads(frame["data"].decode("utf-8","ignore"))
            msgtype = j.get("msgtype")
            msg_b64 = j.get("msg","")
            errcode = j.get("errcode")
            print(f"  opcode={frame['opcode']} msgtype={msgtype} errcode={errcode} msg_b64={msg_b64!r}")
            if msg_b64:
                try:
                    decoded = base64.b64decode(msg_b64)
                    print(f"    msg decoded hex: {decoded.hex()}")
                    print(f"    msg decoded bytes: {list(decoded)}")
                except: pass
        except:
            print(f"  opcode={frame['opcode']} data_hex={frame['data'][:20].hex()}")

# ─── PARTE 2: Enviar PONG (msgtype=4) ──────────────────────

print("\n" + "=" * 60)
print("WS PARTE 2 — Enviar PONG (4)")
print("=" * 60)

pong_msg = json.dumps({"msgtype": 4, "msg": "", "errcode": None})
ws_send(sock, pong_msg)
time.sleep(0.5)
frame = ws_recv(sock, timeout=2)
if frame:
    try:
        j = json.loads(frame["data"].decode("utf-8","ignore"))
        print(f"  Resposta ao PONG: msgtype={j.get('msgtype')} errcode={j.get('errcode')}")
    except:
        print(f"  Resposta ao PONG (raw): {frame['data'][:50].hex()}")
else:
    print("  Sem resposta ao PONG.")

# ─── PARTE 3: Tentar SERVER_AUTH (msgtype=10) com token anão ──

print("\n" + "=" * 60)
print("WS PARTE 3 — SERVER_AUTH com token anão (uid=137027)")
print("=" * 60)

# O payload do SERVER_AUTH provavelmente é protobuf com o token
# Tentamos com o token como string simples (field 1) = uid=137027
token_anao = "137027"

# Protobuf: field 1 = string(token)
proto_payload = encode_protobuf_string(1, token_anao)
msg_b64 = base64.b64encode(proto_payload).decode()

auth_msg = json.dumps({"msgtype": 10, "msg": msg_b64, "errcode": None})
print(f"  Enviando SERVER_AUTH: {auth_msg}")
ws_send(sock, auth_msg)

time.sleep(1)
for _ in range(5):
    frame = ws_recv(sock, timeout=2)
    if frame:
        try:
            j = json.loads(frame["data"].decode("utf-8","ignore"))
            print(f"  Resposta: msgtype={j.get('msgtype')} errcode={j.get('errcode')} msg={j.get('msg')!r}")
            if j.get("msgtype") == 2:  # UNLOGIN
                print("  → UNLOGIN (não autenticado)")
            elif j.get("msgtype") == 10:  # SERVER_AUTH resposta
                print("  → SERVER_AUTH resposta!")
            elif j.get("errcode") == 100:  # TOKEN_INVALID
                print("  → TOKEN_INVALID")
        except:
            print(f"  Raw frame: {frame['data'][:50].hex()}")
    else:
        break

sock.close()
print("  Conexão fechada.")

# ─── PARTE 4: Conectar com token válido para comparar ──────────

print("\n" + "=" * 60)
print("WS PARTE 4 — Conectar com token no header e comparar")
print("=" * 60)

# Login pra token válido
import urllib.request, urllib.error
def login():
    pl = {"appChannel":"pc","appPackageName":"com.slots.big","deviceId":"0beb614f",
          "deviceModel":"WEB","deviceVersion":"WEB","appVersion":"1.0.0",
          "sysTimezone":None,"sysLanguage":None,"phone":"21998498419","password":"21998498419"}
    h = {"User-Agent":"Mozilla/5.0","Content-Type":"application/json"}
    r = urllib.request.Request(BASE+"/prod-api/player/sign-in",
                               data=json.dumps(pl).encode(), headers=h, method="POST")
    with urllib.request.urlopen(r, timeout=10, context=ctx) as resp:
        b = json.loads(resp.read())
        return b["data"]["token"], b["data"].get("connection",{})

try:
    valid_token, conn_info = login()
    print(f"  Token: {valid_token}")
    print(f"  WS connection info: {conn_info}")

    # O connection.ip e port dizem qual WS usar
    ws_ip = conn_info.get("ip","")
    port  = conn_info.get("port", 3001)
    print(f"  WS IP da resposta: {ws_ip}")

    # Conectar com token no header
    sock2, resp2 = ws_connect(HOST, WS_PATH, token=valid_token)
    if "101" in resp2:
        print(f"  ✅ Conectado com token no header!")
        # Receber frames por 5 seg
        start = time.time()
        while time.time() - start < 5:
            frame2 = ws_recv(sock2, timeout=1)
            if frame2:
                try:
                    j2 = json.loads(frame2["data"].decode("utf-8","ignore"))
                    print(f"  Frame: msgtype={j2.get('msgtype')} errcode={j2.get('errcode')}")
                except:
                    print(f"  Raw: {frame2['data'][:20].hex()}")
        sock2.close()
    else:
        print(f"  Resposta: {resp2[:200]}")

except Exception as ex:
    print(f"  [ERRO]: {ex}")

# ─── PARTE 5: Tentar SERVER_AUTH com token completo válido ─────

print("\n" + "=" * 60)
print("WS PARTE 5 — SERVER_AUTH com token completo no payload")
print("=" * 60)

try:
    valid_token2, _ = login()
    sock3, resp3 = ws_connect(HOST, WS_PATH)

    if "101" in resp3:
        # Protobuf: field 1 = string(token_completo)
        proto2 = encode_protobuf_string(1, valid_token2)
        msg_b64_2 = base64.b64encode(proto2).decode()
        auth_msg2 = json.dumps({"msgtype": 10, "msg": msg_b64_2, "errcode": None})
        print(f"  Enviando SERVER_AUTH com token real...")
        ws_send(sock3, auth_msg2)

        time.sleep(1)
        for _ in range(10):
            f3 = ws_recv(sock3, timeout=2)
            if f3:
                try:
                    j3 = json.loads(f3["data"].decode("utf-8","ignore"))
                    mt = j3.get("msgtype")
                    ec = j3.get("errcode")
                    msg = j3.get("msg","")
                    print(f"  Frame: msgtype={mt} errcode={ec} msg={msg!r}")
                    if mt == 11:  # SYNC_ONLINE_STATUS
                        print("  → SYNC_ONLINE_STATUS — AUTENTICADO!")
                        if msg:
                            try:
                                decoded = base64.b64decode(msg)
                                print(f"    payload hex: {decoded.hex()}")
                            except: pass
                    elif ec == 100:
                        print("  → TOKEN_INVALID")
                except:
                    print(f"  Raw: {f3['data'][:30].hex()}")
            else:
                print("  (timeout)")
                break
        sock3.close()
except Exception as ex:
    print(f"  [ERRO parte 5]: {ex}")

print("\n✅ WebSocket exploration concluída.")

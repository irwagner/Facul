"""
Teste final e correto do WS auth.
  errcode=null → sucesso
  errcode=100  → TOKEN_INVALID
  errcode=101  → PLAYER_NOT_FOUND
"""
import ssl, socket, base64, struct, json, time
import urllib.request, urllib.error
from datetime import datetime

ctx = ssl.create_default_context()
ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
HOST = "ds.amizade777.com"
WS_PATH = "/websocket6"
BASE = "https://ds.amizade777.com"

def varint(v):
    out = b""
    while v > 0x7F: out += bytes([(v & 0x7F) | 0x80]); v >>= 7
    return out + bytes([v & 0x7F])

def field_string(fnum, s):
    b = s.encode() if isinstance(s, str) else s
    return varint((fnum << 3) | 2) + varint(len(b)) + b

def ws_connect():
    key = base64.b64encode(b"kiro_final_test_2026!").decode()
    hdrs = (f"GET {WS_PATH} HTTP/1.1\r\nHost: {HOST}\r\n"
            f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n"
            f"Origin: https://{HOST}\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
    raw = socket.create_connection((HOST, 443), timeout=10)
    ssl_s = ctx.wrap_socket(raw, server_hostname=HOST)
    ssl_s.send(hdrs.encode())
    resp = ssl_s.recv(4096).decode("utf-8","ignore")
    return ssl_s if "101" in resp else None

def ws_send(s, obj):
    payload = json.dumps(obj).encode()
    mask = b'\x42\x13\x71\x9a'
    h = bytearray([0x81, 0x80 | len(payload)]) if len(payload)<126 else bytearray([0x81, 0xFE]) + struct.pack(">H",len(payload))
    h += mask
    s.send(bytes(h) + bytes(p ^ mask[i%4] for i,p in enumerate(payload)))

def ws_recv(s, timeout=3):
    s.settimeout(timeout)
    try:
        h = b""
        while len(h) < 2: c = s.recv(2-len(h)); h += c if c else (lambda: (_ for _ in ()).throw(EOFError()))()
        op = h[0] & 0xF; ln = h[1] & 0x7F
        if ln == 126: ln = struct.unpack(">H", s.recv(2))[0]
        data = b""
        while len(data) < min(ln, 65536):
            c = s.recv(min(ln, 65536) - len(data))
            if not c: break
            data += c
        try: return json.loads(data.decode("utf-8","ignore"))
        except: return {"_hex": data[:32].hex()}
    except socket.timeout: return None
    except: return None

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

def test_ws_token(token_str, label):
    print(f"\n  [{label}]")
    s = ws_connect()
    if not s: print("  Não conectou"); return

    # Heartbeat
    h = ws_recv(s, 2)
    if h: print(f"    Heartbeat: {h}")

    # Login
    proto = field_string(1, token_str)
    msg_b64 = base64.b64encode(proto).decode()
    ws_send(s, {"msgtype": 100, "msg": msg_b64, "errcode": None})
    print(f"    Enviado PLAYER_LOGIN_REQ proto_hex={proto.hex()}")

    # Aguardar resposta por 8 segundos
    for _ in range(16):
        r = ws_recv(s, 0.5)
        if r:
            mt = r.get("msgtype"); ec = r.get("errcode"); msg = r.get("msg")
            print(f"    Frame: msgtype={mt} errcode={ec} msg={msg!r}")
            if mt == 101:  # PLAYER_LOGIN_REPLY
                if ec is None or ec == 0:
                    print(f"    🔴 LOGIN BEM-SUCEDIDO! errcode={ec}")
                    if msg:
                        try:
                            import base64 as b64
                            raw = b64.b64decode(msg)
                            print(f"    proto_payload hex: {raw.hex()}")
                        except: pass
                else:
                    print(f"    ❌ TOKEN INVÁLIDO: errcode={ec}")
            elif mt == 2:
                print(f"    UNLOGIN (não autenticado)")
            elif mt == 1:
                pass  # heartbeat, ignorar
    s.close()

# ─── Verificar primeiro se o WS funciona ─────────────────────

print("=" * 60)
print("VERIFICAÇÃO INICIAL — WS aceita conexão?")
print("=" * 60)

s = ws_connect()
if s:
    print("✅ WS conectado")
    h = ws_recv(s, 3)
    print(f"  Heartbeat: {h}")
    s.close()
else:
    print("❌ Não conectou")
    exit()

# ─── Testes com diferentes tokens ─────────────────────────────

print("\n" + "=" * 60)
print("TESTES DE AUTH")
print("=" * 60)

# Token anão
test_ws_token("137027", "token anão uid=137027")
time.sleep(1)
test_ws_token("1", "token anão uid=1")
time.sleep(1)

# Token válido (login imediato antes do WS)
try:
    valid_tok = login()
    print(f"\n  Token válido obtido: {valid_tok}")
    test_ws_token(valid_tok, "token válido completo")
except Exception as ex:
    print(f"\n  [ERRO login]: {ex}")

print(f"\n✅ Concluído em {datetime.now().isoformat()}")

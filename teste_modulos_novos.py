"""
Roda os 4 modulos novos contra o alvo real, sem precisar de Burp:
    1. SSRF detector — passa pelos endpoints publicos do /japi/
    2. Cache poisoning checker — testa todos os 18 headers contra a home
    3. CORS misconfig checker — testa /japi/user/captcha/image (publico)
    4. WS protobuf inspector — captura 1 frame e mostra summary

Usa transports leves baseados em urllib (passivo, sem governanca porque
isso eh smoke do toolkit, nao um pentest oficial).
"""
from __future__ import annotations

import asyncio
import gzip
import json
import sys
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from toolkit.execution.checks import (
    cache_poison as cp_check,
    cors as cors_check,
    ssrf as ssrf_check,
)
from toolkit.analysis.classifiers import (
    cache_poison as cp_cls,
    cors as cors_cls,
    ssrf as ssrf_cls,
)
from toolkit.discovery import ws_inspector

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"


def banner(t):
    print(f"\n{'=' * 70}\n  {t}\n{'=' * 70}")


# ---------------------------------------------------------------------
# Transports
# ---------------------------------------------------------------------


class _R:
    def __init__(self, status, body=b"", headers=None, elapsed_ms=0):
        self.status = status
        self.body = body
        self.headers = headers or {}
        self.elapsed_ms = elapsed_ms


def transport_simple(url, *, method="GET", headers=None, timeout=10.0):
    h = {"User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "gzip"}
    if headers:
        h.update(headers)
    req = Request(url, method=method, headers=h)
    start = time.time()
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            if resp.headers.get("content-encoding") == "gzip":
                raw = gzip.decompress(raw)
            elapsed_ms = int((time.time() - start) * 1000)
            return _R(resp.status, raw, dict(resp.getheaders()), elapsed_ms)
    except HTTPError as exc:
        elapsed_ms = int((time.time() - start) * 1000)
        try:
            raw = exc.read()
        except Exception:
            raw = b""
        return _R(exc.code, raw, dict(exc.headers or {}), elapsed_ms)
    except Exception as exc:
        return _R(None, str(exc).encode(), {}, 0)


# Transport adapters that match each check's signature

def ssrf_transport(url):
    return transport_simple(url)


def cache_transport(url, headers=None):
    return transport_simple(url, headers=headers or {})


def cors_transport(url, *, method="GET", headers=None):
    return transport_simple(url, method=method, headers=headers or {})


# ---------------------------------------------------------------------
# 1. SSRF
# ---------------------------------------------------------------------


def step_ssrf():
    banner("[1/4] SSRF DETECTOR — endpoints publicos do /japi/")
    # Vamos rodar contra um endpoint publico que aceita GET (mesmo sem URL
    # parametro vamos confirmar que nenhum payload retorna sinal de leak).
    target = "https://ds.amizade777.com/japi/activity/redPacketRain/redPacketRainActivityList"
    print(f"  alvo: {target}")
    print(f"  parametros padrao: {ssrf_check.DEFAULT_PARAMETERS[:5]}...")
    print(f"  payloads padrao: {len(ssrf_check.DEFAULT_PAYLOADS)} entradas")

    # So roda 1 parametro pra ser rapido
    result = ssrf_check.check_ssrf_param(
        target, "url", transport=ssrf_transport,
        # subset pra nao floodar — 8 dos 25 payloads default
        payloads=ssrf_check.DEFAULT_PAYLOADS[:8],
    )
    cls = ssrf_cls.analyze_ssrf(result)
    print(f"\n  attempts: {len(result.attempts)}")
    for a in result.attempts:
        print(f"    {a.payload[:50]:<50s} -> status={a.status} ms={a.elapsed_ms}")
    print(f"\n  vulneravel: {cls.is_vulnerable}")
    timing = ssrf_cls.detect_timing_oracle(result)
    print(f"  timing oracle suspeitos: {len(timing)}")
    for t in timing:
        print(f"    {t.payload[:60]} ms={t.elapsed_ms}")
    return {"vulnerable": cls.is_vulnerable,
            "findings": [f.__dict__ for f in cls.findings],
            "timing_suspects": [t.payload for t in timing]}


# ---------------------------------------------------------------------
# 2. Cache poisoning
# ---------------------------------------------------------------------


def step_cache_poison():
    banner("[2/4] CACHE POISONING — home de ds.amizade777.com")
    target = "https://ds.amizade777.com/"
    result = cp_check.check_cache_poison(target, transport=cache_transport)
    cls = cp_cls.analyze_cache_poison(result)
    print(f"  baseline status={result.baseline_status} size={result.baseline_size}")
    print(f"  probes: {len(result.probes)}")
    print(f"  vulneravel: {cls.is_vulnerable}")
    if cls.findings:
        print(f"\n  FINDINGS ({len(cls.findings)}):")
        for f in cls.findings:
            print(f"    [{f.severity}] {f.header}={f.value}")
            print(f"        razao: {f.reason}")
    else:
        print("  nenhum finding")
    return {
        "vulnerable": cls.is_vulnerable,
        "findings": [f.__dict__ for f in cls.findings],
    }


# ---------------------------------------------------------------------
# 3. CORS
# ---------------------------------------------------------------------


def step_cors():
    banner("[3/4] CORS MISCONFIG — endpoints publicos")
    out = {}
    for url in [
        "https://ds.amizade777.com/japi/user/captcha/image",
        "https://ds.amizade777.com/japi/activity/redPacketRain/redPacketRainActivityList",
        "https://ds.amizade777.com/japi/invite/api/finger/download?packageName=com.slots.big",
    ]:
        result = cors_check.check_cors(url, transport=cors_transport)
        cls = cors_cls.analyze_cors(result)
        print(f"\n  {url}")
        print(f"    probes: {len(result.probes)}, vulneravel: {cls.is_vulnerable}")
        # Mostrar acao/acac do primeiro probe pra ver o que o backend envia
        for p in result.probes[:2]:
            print(f"      origin={p.origin!r} method={p.method} "
                  f"acao={p.acao!r} acac={p.acac!r}")
        if cls.findings:
            for f in cls.findings:
                print(f"    [{f.severity}] {f.method} from {f.origin}: {f.reason}")
        out[url] = {
            "vulnerable": cls.is_vulnerable,
            "probes": len(result.probes),
            "findings": [f.__dict__ for f in cls.findings],
        }
    return out


# ---------------------------------------------------------------------
# 4. WS inspector
# ---------------------------------------------------------------------


async def _ws_capture():
    import websockets
    frames = []
    try:
        async with websockets.connect(
            "wss://ds.amizade777.com/websocket6",
            origin="https://ds.amizade777.com",
            ping_interval=None, close_timeout=2,
        ) as ws:
            try:
                msg = await asyncio.wait_for(ws.recv(), timeout=15)
                frames.append(msg)
            except asyncio.TimeoutError:
                pass
    except Exception as exc:
        return [], str(exc)
    return frames, None


def step_ws_inspect():
    banner("[4/4] WS PROTOBUF INSPECTOR — frame inicial do websocket6")
    frames, err = asyncio.run(_ws_capture())
    if err:
        print(f"  erro: {err}")
        return {"error": err}
    print(f"  frames capturados: {len(frames)}")

    out = []
    for i, msg in enumerate(frames):
        # Frame inicial vem como JSON com base64 dentro
        if isinstance(msg, str):
            print(f"\n  frame {i} (text): {msg[:200]}")
            try:
                obj = json.loads(msg)
                if "msg" in obj and isinstance(obj["msg"], str):
                    import base64
                    inner = base64.b64decode(obj["msg"])
                    summary = ws_inspector.summarise_frame(inner)
                    print(f"    inner protobuf summary: {summary}")
                    out.append({"text_envelope": obj, "inner_summary": summary})
            except Exception as exc:
                out.append({"text": msg[:300], "parse_error": str(exc)})
        else:
            print(f"\n  frame {i} (bytes, {len(msg)}): {msg[:64].hex()}")
            summary = ws_inspector.summarise_frame(msg)
            print(f"    summary: {summary}")
            out.append({"size": len(msg), "summary": summary})

    # Extract message catalog from message.js
    bundle_path = ROOT / "bundles" / "ds.amizade777.com_message.js"
    if bundle_path.exists():
        text = bundle_path.read_text(encoding="utf-8", errors="replace")
        catalog = ws_inspector.extract_message_catalog(text)
        print(f"\n  CATALOG do message.js: {len(catalog.messages)} mensagens")
        for suffix, names in sorted(catalog.by_suffix.items()):
            print(f"    {suffix}: {len(names)}  amostra: {names[:3]}")
        out_catalog = {
            "total": len(catalog.messages),
            "by_suffix": {k: len(v) for k, v in catalog.by_suffix.items()},
            "first_30": catalog.messages[:30],
        }
    else:
        out_catalog = None

    return {"frames": out, "catalog": out_catalog}


def main():
    out = {
        "ssrf": step_ssrf(),
        "cache_poison": step_cache_poison(),
        "cors": step_cors(),
        "ws": step_ws_inspect(),
    }
    Path("teste_modulos_novos.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    print("\n  Salvo em teste_modulos_novos.json")


if __name__ == "__main__":
    main()

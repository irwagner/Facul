"""
Baixa todos os bundles JS de ds. e m., extrai endpoints, segredos
potenciais, hashes, configuracoes e roda os classificadores do toolkit.

Salva resultado em analise_bundles.json + um diretorio bundles/ com os
arquivos baixados.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))
BUNDLES = ROOT / "bundles"
BUNDLES.mkdir(exist_ok=True)

from toolkit.analysis.classifiers import secrets as secrets_cls
from toolkit.execution.checks import jwt_inspector

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
TARGETS = ["ds.amizade777.com", "m.amizade777.com"]


def fetch(url: str, *, timeout: float = 30.0) -> tuple[int, dict, bytes]:
    req = Request(url, headers={"User-Agent": UA, "Accept-Encoding": "gzip, deflate"})
    with urlopen(req, timeout=timeout) as resp:
        body = resp.read()
        if resp.headers.get("content-encoding") == "gzip":
            body = gzip.decompress(body)
        return resp.status, dict(resp.getheaders()), body


def list_bundles_from_html(html: str, base: str) -> list[str]:
    """Extrai URLs de .js e .css referenciadas no HTML."""
    out = set()
    for m in re.findall(r'(?:src|href)\s*=\s*["\']([^"\']+\.(?:js|css)[^"\']*)["\']', html, re.I):
        if m.startswith("//"):
            url = "https:" + m
        elif m.startswith("http"):
            url = m
        elif m.startswith("/"):
            url = base.rstrip("/") + m
        else:
            url = base.rstrip("/") + "/" + m
        out.add(url)
    return sorted(out)


def extract_endpoints(text: str) -> list[str]:
    patterns = [
        # URLs explicitas
        re.compile(r'["\'](https?://[^"\']{4,200})["\']'),
        # Caminhos /api/... e /prod-api/... e /japi/...
        re.compile(r'["\'](/(?:prod-api|japi|api|admin|manage)/[a-zA-Z0-9_\-/\.\?=&]{1,200})["\']'),
    ]
    found = set()
    for p in patterns:
        for m in p.findall(text):
            if any(skip in m for skip in ("application/", "text/", "image/", "video/")):
                continue
            found.add(m)
    return sorted(found)[:300]


def extract_websockets(text: str) -> list[str]:
    return sorted(set(re.findall(r"wss?://[a-zA-Z0-9\-\.]+(?::\d+)?[a-zA-Z0-9_\-/\.]*", text)))[:50]


def extract_potential_secrets(text: str) -> dict:
    """Aplica regexes do toolkit + extras."""
    findings = {
        "ethereum_pk": list(set(re.findall(r"\b0x[a-fA-F0-9]{64}\b", text))),
        "ethereum_addr": list(set(re.findall(r"\b0x[a-fA-F0-9]{40}\b", text))),
        "aws_access_key": list(set(re.findall(r"\bAKIA[0-9A-Z]{16}\b", text))),
        "google_api_key": list(set(re.findall(r"\bAIza[0-9A-Za-z\-_]{35}\b", text))),
        "stripe_live": list(set(re.findall(r"\bsk_live_[0-9a-zA-Z]{24,}\b", text))),
        "stripe_test": list(set(re.findall(r"\bsk_test_[0-9a-zA-Z]{24,}\b", text))),
        "jwt_tokens": list({tok for tok in re.findall(r"[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}", text) if tok.count(".") == 2})[:20],
        "private_pem": list(set(re.findall(r"-----BEGIN[^-]+PRIVATE KEY-----", text))),
        "generic_apikey": list(set(re.findall(r"(?i)(?:api[_\-]?key|apikey|api_secret)[\"'\s:=]+[\"']([A-Za-z0-9_\-]{20,})[\"']", text)))[:50],
        "passwords": list(set(re.findall(r"(?i)(?:password|passwd|pwd)[\"'\s:=]+[\"']([^\"'\s]{4,50})[\"']", text)))[:50],
    }
    return findings


def main() -> None:
    output: dict = {"targets": {}}
    for tgt in TARGETS:
        print(f"\n========== {tgt} ==========")
        # 1) buscar HTML
        try:
            _, _, html_bytes = fetch(f"https://{tgt}/")
            html = html_bytes.decode("utf-8", errors="replace")
        except Exception as exc:
            print(f"  ERRO ao buscar HTML: {exc}")
            output["targets"][tgt] = {"error": str(exc)}
            continue
        bundles = list_bundles_from_html(html, f"https://{tgt}")
        print(f"  {len(bundles)} bundles referenciados")
        # 2) Adiciona alguns paths comuns onde o Vite costuma jogar bundles
        common_extra = [
            f"https://{tgt}/assets/index.js",
            f"https://{tgt}/assets/main.js",
            f"https://{tgt}/index.js",
        ]
        bundles_full = bundles + [u for u in common_extra if u not in bundles]

        per_bundle = []
        all_text_chunks: list[str] = []
        for url in bundles_full:
            try:
                status, headers, body = fetch(url, timeout=45)
                if status != 200:
                    per_bundle.append({"url": url, "status": status, "size": 0})
                    continue
                text = body.decode("utf-8", errors="replace")
                sha = hashlib.sha256(body).hexdigest()[:16]
                fname = url.rsplit("/", 1)[-1].split("?")[0] or "bundle.bin"
                local = BUNDLES / f"{tgt}_{fname}"
                local.write_bytes(body)
                ctype = headers.get("content-type") or headers.get("Content-Type") or ""
                per_bundle.append({
                    "url": url,
                    "status": status,
                    "size": len(body),
                    "sha256_16": sha,
                    "ctype": ctype.split(";")[0].strip(),
                    "saved_as": local.name,
                })
                if "javascript" in ctype or url.endswith(".js"):
                    all_text_chunks.append(text)
                print(f"  [{status}] {url}  ({len(body)} bytes, sha={sha})")
            except (HTTPError, URLError) as exc:
                per_bundle.append({"url": url, "error": str(exc)})
                print(f"  [ERR] {url}  {exc}")
            except Exception as exc:
                per_bundle.append({"url": url, "error": f"{type(exc).__name__}: {exc}"})
                print(f"  [ERR] {url}  {exc}")

        merged = "\n".join(all_text_chunks)
        print(f"\n  total {len(merged)} chars de codigo JS unificado")

        endpoints = extract_endpoints(merged)
        websockets = extract_websockets(merged)
        secret_hits = extract_potential_secrets(merged)

        # JWT inspecao (caso algum token esteja embutido)
        jwt_reports = []
        for tok in secret_hits.get("jwt_tokens") or []:
            try:
                rep = jwt_inspector.inspect(tok)
                if rep.valid_structure or rep.issues:
                    jwt_reports.append(rep.to_dict())
            except Exception:
                pass

        # secrets analyzer do toolkit
        try:
            sec_report = secrets_cls.analyze_bundle_hits({"bundle.merged.js": merged})
            sec_findings = [f.__dict__ if hasattr(f, "__dict__") else f for f in sec_report.findings]
        except Exception as exc:
            sec_findings = [{"error": str(exc)}]

        # heuristicas extras
        version_hits = list(set(re.findall(r'\b(?:version|VERSION|appVersion)\s*[:=]\s*["\']([^"\']+)["\']', merged)))
        device_hits = list(set(re.findall(r'\bdeviceId\s*[:=]\s*["\']?([0-9a-fA-F\-]{8,})["\']?', merged)))
        config_hits = list(set(re.findall(r'\b(?:baseURL|BASE_URL|api_base|apiBase)\s*[:=]\s*["\']([^"\']+)["\']', merged)))

        print(f"  endpoints achados: {len(endpoints)}")
        print(f"  websockets:        {len(websockets)}")
        print(f"  jwt-like tokens:   {len(secret_hits['jwt_tokens'])}")
        print(f"  PEM private keys:  {len(secret_hits['private_pem'])}")
        print(f"  Ethereum keys:     {len(secret_hits['ethereum_pk'])}")
        print(f"  AWS access keys:   {len(secret_hits['aws_access_key'])}")
        print(f"  Google API keys:   {len(secret_hits['google_api_key'])}")
        print(f"  generic apikeys:   {len(secret_hits['generic_apikey'])}")
        print(f"  passwords:         {len(secret_hits['passwords'])}")
        print(f"  versoes mencionadas: {version_hits}")
        print(f"  baseURL/api_base:  {config_hits}")

        # imprimir os primeiros endpoints unicos relevantes
        api_eps = [e for e in endpoints if any(p in e for p in ("/prod-api/", "/japi/", "/api/"))]
        print(f"\n  EXEMPLOS DE ENDPOINTS DA API ({len(api_eps)}):")
        for e in api_eps[:25]:
            print(f"    {e}")

        output["targets"][tgt] = {
            "html_size": len(html),
            "bundles_referenced": bundles,
            "bundle_results": per_bundle,
            "merged_size": len(merged),
            "endpoints": endpoints,
            "api_endpoints": api_eps,
            "websockets": websockets,
            "secrets_regex": secret_hits,
            "secrets_classifier": sec_findings,
            "jwt_reports": jwt_reports,
            "version_hits": version_hits,
            "device_hits": device_hits,
            "config_hits": config_hits,
        }

    out_file = ROOT / "analise_bundles.json"
    out_file.write_text(json.dumps(output, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    print(f"\nResultado salvo em: {out_file}")


if __name__ == "__main__":
    main()

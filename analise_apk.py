"""
Baixa o APK Amizade777.apk e extrai:
  - Endpoints (URLs/paths) do classes.dex e dos resources
  - Strings interessantes (chaves API, secrets, internal IPs)
  - Manifest (AndroidManifest.xml) com permissoes e activities

Nao precisa de apktool — usa apenas zipfile, regex e parsing manual de
strings UTF-8/UTF-16. Cobre 80% do que o apktool entregaria sem
dependencia externa.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
APK_URL = "https://sx.megaslott.com/download/Amizade777.apk"
APK_PATH = ROOT / "Amizade777.apk"
EXTRACT_DIR = ROOT / "apk_extracted"
EXTRACT_DIR.mkdir(exist_ok=True)

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"


def download_apk() -> None:
    if APK_PATH.exists() and APK_PATH.stat().st_size > 0:
        print(f"  APK ja baixado: {APK_PATH} ({APK_PATH.stat().st_size} bytes)")
        return
    print(f"  baixando {APK_URL}")
    req = Request(APK_URL, headers={"User-Agent": UA})
    with urlopen(req, timeout=120) as resp:
        APK_PATH.write_bytes(resp.read())
    sha = hashlib.sha256(APK_PATH.read_bytes()).hexdigest()
    print(f"  baixado: {APK_PATH.stat().st_size} bytes  sha256={sha}")


def extract_apk_strings() -> bytes:
    """Extrai bytes brutos de classes.dex + .so + .arsc + raw assets."""
    print(f"\n  abrindo {APK_PATH}")
    chunks: list[bytes] = []
    with zipfile.ZipFile(APK_PATH) as z:
        for member in z.namelist():
            if member.endswith(".dex") or member.endswith(".so") or \
               member.endswith(".arsc") or member.startswith("assets/") or \
               "AndroidManifest" in member:
                try:
                    data = z.read(member)
                    chunks.append(data)
                    out = EXTRACT_DIR / member.replace("/", "_").replace("\\", "_")
                    out.write_bytes(data)
                    print(f"    extraido {member}: {len(data)} bytes")
                except Exception as exc:
                    print(f"    erro extraindo {member}: {exc}")
    return b"\n".join(chunks)


def list_apk_files() -> list[str]:
    with zipfile.ZipFile(APK_PATH) as z:
        return z.namelist()


def find_strings(blob: bytes, *, min_len: int = 6) -> list[str]:
    """Extrai strings ASCII e UTF-16-LE do blob."""
    results: set[str] = set()
    # ASCII
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, blob):
        results.add(m.group().decode("ascii", errors="ignore"))
    # UTF-16 LE basico
    pattern = b"(?:[\x20-\x7e]\x00){%d,}" % min_len
    for m in re.finditer(pattern, blob):
        try:
            s = m.group().decode("utf-16-le", errors="ignore").rstrip("\x00")
            if len(s) >= min_len:
                results.add(s)
        except Exception:
            continue
    return sorted(results)


def main() -> None:
    print("[1/3] DOWNLOAD DO APK")
    download_apk()

    print("\n[2/3] LISTAGEM DE ARQUIVOS DO APK")
    files = list_apk_files()
    print(f"  {len(files)} arquivos no APK")
    interesting = [f for f in files if f.endswith(".dex") or f.endswith(".so") or "META-INF" in f or f == "AndroidManifest.xml" or f.startswith("assets/")]
    print(f"  {len(interesting)} arquivos interessantes:")
    for f in interesting[:50]:
        print(f"    {f}")

    print("\n[3/3] EXTRACAO E ANALISE DE STRINGS")
    blob = extract_apk_strings()
    strings = find_strings(blob, min_len=6)
    print(f"\n  {len(strings)} strings unicas extraidas (>=6 chars)")

    # Filtrar coisas relevantes
    url_re = re.compile(r"^https?://[a-zA-Z0-9\-\.]+(?::\d+)?(/[^\s\"'<>]*)?$")
    api_path_re = re.compile(r"^/(?:prod-api|japi|api|admin|manage)(?:/[a-zA-Z0-9_\-\.\?=&]+)*$")
    ws_re = re.compile(r"^wss?://[a-zA-Z0-9\-\.]+(?::\d+)?")
    domain_re = re.compile(r"\.(?:com|net|org|io|app|cloud)$")
    internal_ip_re = re.compile(r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}")
    aws_re = re.compile(r"AKIA[0-9A-Z]{16}")
    google_re = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
    private_pem = re.compile(r"-----BEGIN .* PRIVATE KEY-----")

    urls = [s for s in strings if url_re.match(s)]
    api_paths = [s for s in strings if api_path_re.match(s)]
    websockets = [s for s in strings if ws_re.match(s)]
    internal_ips = [s for s in strings if internal_ip_re.match(s)]
    aws_keys = [s for s in strings if aws_re.search(s)]
    google_keys = [s for s in strings if google_re.search(s)]
    pem_keys = [s for s in strings if private_pem.search(s)]
    
    # Domains uniques (extrai dominio das URLs)
    domains = set()
    for u in urls:
        try:
            host = u.split("//", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
            domains.add(host)
        except Exception:
            pass

    # API paths internos (caminhos sem schema)
    api_path_only_re = re.compile(r"^(/(?:prod-api|japi|api)(?:/[a-zA-Z0-9_\-]+)+)$")
    pure_api_paths = sorted({s for s in strings if api_path_only_re.match(s)})

    # Strings que indicam JWT
    jwt_re = re.compile(r"^(?:eyJ[A-Za-z0-9_\-]{4,})$")
    jwt_starts = [s for s in strings if jwt_re.match(s)]

    # Chaves de configuracao
    config_keys = [s for s in strings if re.search(r"^(?:apiKey|api_key|secret|secretKey|password|pwd|baseUrl|baseURL|API_BASE)$", s, re.I)]

    # Tokens HMAC / hash
    hex_strings = [s for s in strings if re.match(r"^[a-f0-9]{16,64}$", s)]
    md5_only = [s for s in hex_strings if len(s) == 32]
    sha1_only = [s for s in hex_strings if len(s) == 40]

    out: dict = {
        "apk_url": APK_URL,
        "apk_size": APK_PATH.stat().st_size,
        "apk_sha256": hashlib.sha256(APK_PATH.read_bytes()).hexdigest(),
        "files_total": len(files),
        "all_files": files,
        "strings_total": len(strings),
        "domains": sorted(domains),
        "urls": sorted(urls)[:200],
        "websockets": sorted(websockets),
        "api_paths_unique": pure_api_paths,
        "internal_ips": sorted(internal_ips),
        "aws_keys": aws_keys,
        "google_keys": google_keys,
        "pem_keys": pem_keys,
        "jwt_starts": jwt_starts[:30],
        "config_keys_seen": config_keys,
        "md5_count": len(md5_only),
        "md5_first_20": md5_only[:20],
        "sha1_count": len(sha1_only),
        "sha1_first_20": sha1_only[:20],
    }

    print(f"\n  DOMINIOS UNICOS NO APK ({len(domains)}):")
    for d in sorted(domains):
        print(f"    {d}")

    print(f"\n  WEBSOCKETS ({len(websockets)}):")
    for w in sorted(websockets):
        print(f"    {w}")

    print(f"\n  API PATHS NO APK ({len(pure_api_paths)}):")
    for p in pure_api_paths[:80]:
        print(f"    {p}")

    print(f"\n  IPS INTERNOS ({len(internal_ips)}):")
    for ip in sorted(internal_ips):
        print(f"    {ip}")

    print(f"\n  AWS KEYS:    {len(aws_keys)}  |  GOOGLE: {len(google_keys)}  |  PEM: {len(pem_keys)}")
    if aws_keys:
        for k in aws_keys[:5]:
            print(f"    [AWS] {k[:24]}...")
    if google_keys:
        for k in google_keys[:5]:
            print(f"    [GOOGLE] {k[:24]}...")

    # JWTs
    print(f"\n  JWT-START (eyJ): {len(jwt_starts)}")

    Path("analise_apk.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    print("\n  Salvo em analise_apk.json")


if __name__ == "__main__":
    main()

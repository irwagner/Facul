"""
Varredura completa de diretórios, arquivos sensíveis e endpoints
nos dois subdomínios ativos.
"""
import urllib.request, ssl, json, socket, time

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

bases = [
    "https://ds.amizade777.com",
    "https://m.amizade777.com",
]

paths = [
    # Admin panels
    "/admin", "/adm", "/administrator", "/admin/login", "/admin/dashboard",
    "/wp-admin", "/phpmyadmin", "/cpanel", "/manage", "/manager",
    "/management", "/backoffice", "/console", "/control", "/portal", "/backend",
    # APIs e docs
    "/api", "/api/v1", "/api/v2", "/graphql", "/swagger", "/swagger-ui",
    "/swagger.json", "/openapi.json", "/api-docs", "/redoc",
    # Arquivos sensíveis
    "/.env", "/.env.local", "/.env.production", "/.gitignore",
    "/.git/config", "/.git/HEAD", "/composer.json", "/package.json",
    "/config.json", "/config.php", "/settings.json",
    "/database.yml", "/Dockerfile", "/docker-compose.yml",
    "/.htaccess", "/web.config",
    # Rotas do app
    "/deposit", "/withdraw", "/wallet", "/balance",
    "/recharge", "/payment", "/transfer", "/transaction",
    "/register", "/signup", "/signin", "/login",
    "/profile", "/account", "/settings", "/dashboard",
    # Monitoramento
    "/health", "/healthz", "/status", "/ping", "/metrics",
    "/actuator", "/actuator/health", "/server-status",
    "/debug", "/trace", "/info", "/version",
    # Outros
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/manifest.json", "/favicon.ico",
    # Específicos do sistema de cassino
    "/game", "/games", "/casino", "/slots", "/sport",
    "/vip", "/bonus", "/promo", "/promotion",
    "/invite", "/referral", "/affiliate",
    "/withdraw-record", "/deposit-record",
    "/transaction-history", "/bet-history",
    "/customer-service", "/support", "/chat",
    "/notification", "/announcement", "/news",
    "/ranking", "/leaderboard", "/jackpot",
    # WebSocket e real-time
    "/ws", "/websocket", "/socket.io",
    "/websocket6", "/ws6",
    # Possíveis paineis admin alternativos
    "/manage/player", "/manage/finance", "/manage/user",
    "/system/admin", "/system/config", "/system/log",
    "/super", "/superadmin", "/root",
    "/ops", "/operator", "/staff",
    # Arquivos de build Vite
    "/assets/env.json", "/assets/config.json",
    "/.vite", "/vite.config.js",
]

def check(base, path):
    url = base + path
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
            status = r.status
            ct = r.headers.get("Content-Type", "")
            body = r.read(500).decode("utf-8", "ignore")
            return status, ct, body
    except urllib.error.HTTPError as e:
        return e.code, "", ""
    except:
        return 0, "", ""

print("=" * 60)
print("VARREDURA DE DIRETÓRIOS E ARQUIVOS SENSÍVEIS")
print("=" * 60)

for base in bases:
    print(f"\n[{base}]")
    for path in paths:
        time.sleep(0.25)
        status, ct, body = check(base, path)

        # Ignorar SPAs (retornam 200 com HTML do Vue.js para tudo)
        is_spa_html = (
            "crossorigin" in body or
            'type="module"' in body or
            "polyfills" in body
        )

        if status == 0:
            continue
        if status == 404:
            continue
        if status == 200 and is_spa_html:
            continue  # SPA redireciona tudo para index.html

        # Resultado interessante
        body_preview = body[:100].replace("\n", " ").replace("\r", "")
        flag = ""
        if status == 200:
            flag = " *** INTERESSANTE ***"
            if "password" in body.lower() or "secret" in body.lower() or "key" in body.lower():
                flag = " *** DADO SENSÍVEL ***"
        print(f"  [{status}] {path}  ({ct[:25]})  {body_preview!r}{flag}")

# Testar portas adicionais nos IPs
print("\n" + "=" * 60)
print("SCAN DE PORTAS NOS IPs")
print("=" * 60)

ips_portas = {
    "18.64.207.79":   [80, 443, 3000, 3001, 5000, 8000, 8080, 8443, 8888, 9000, 9090, 9443],
    "18.161.205.121": [80, 443, 3000, 3001, 5000, 8000, 8080, 8443, 8888, 9000, 9090, 9443],
    "172.16.0.245":   [80, 443, 3001, 3000, 8080, 9000],  # IP interno exposto
}

for ip, portas in ips_portas.items():
    print(f"\n  {ip}:")
    for porta in portas:
        try:
            s = socket.create_connection((ip, porta), timeout=2)
            s.close()
            print(f"    porta {porta}: ABERTA")
        except:
            pass

print("\nConcluído.")

"""
Script para descobrir subdomínios ocultos de um domínio.

Usa duas técnicas passivas:
  1. Certificate Transparency (crt.sh) — registros públicos de certificados SSL
  2. DNS brute-force com wordlist de prefixos comuns

Não precisa de ferramentas externas — só Python puro.

Uso:
    python descobrir_subdominios.py
"""

import json
import socket
import urllib.request

# ============================================================
# CONFIGURE AQUI
# ============================================================
DOMINIO = "amizade777.com"   # <- troque pelo domínio real
# ============================================================

# Prefixos comuns que faculdades e sistemas costumam usar
PREFIXOS_COMUNS = [
    "www", "m", "ds", "api", "app", "portal", "sistema", "aluno",
    "alunos", "professor", "professores", "moodle", "ead", "ava",
    "mail", "webmail", "email", "smtp", "ftp", "vpn", "remote",
    "admin", "adm", "painel", "dashboard", "intranet", "extranet",
    "static", "assets", "cdn", "files", "download", "upload",
    "dev", "test", "staging", "homolog", "hml", "qa", "beta",
    "old", "new", "v2", "v1", "mobile", "web", "wap",
    "api2", "rest", "graphql", "ws", "socket",
    "sso", "auth", "login", "oauth", "id",
    "wiki", "docs", "blog", "news", "forum",
    "erp", "crm", "rh", "financeiro", "academico",
    "biblioteca", "lab", "pesquisa",
    "cloud", "s3", "storage", "backup",
    "monitor", "status", "health",
    "ns1", "ns2", "dns", "mx", "mail2",
]


def buscar_ct_logs(dominio: str) -> list[str]:
    """Busca subdomínios no Certificate Transparency (crt.sh)."""
    print(f"\n[1/3] Buscando em Certificate Transparency (crt.sh) para {dominio}...")
    url = f"https://crt.sh/?q=%.{dominio}&output=json"
    encontrados = set()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "audit-toolkit/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            for entry in data:
                nome = entry.get("name_value", "")
                for linha in nome.splitlines():
                    linha = linha.strip().lstrip("*.")
                    if linha.endswith(f".{dominio}") or linha == dominio:
                        encontrados.add(linha)
        print(f"  -> {len(encontrados)} nomes encontrados em crt.sh")
    except Exception as e:
        print(f"  -> Erro ao consultar crt.sh: {e}")
    return sorted(encontrados)


def brute_force_dns(dominio: str, prefixos: list[str]) -> list[str]:
    """Testa prefixos comuns via DNS para achar subdomínios ativos."""
    print(f"\n[2/3] Testando {len(prefixos)} prefixos via DNS brute-force...")
    ativos = []
    for prefixo in prefixos:
        candidato = f"{prefixo}.{dominio}"
        try:
            ip = socket.gethostbyname(candidato)
            print(f"  [ENCONTRADO] {candidato} -> {ip}")
            ativos.append(candidato)
        except socket.gaierror:
            pass  # não resolve = não existe
    print(f"  -> {len(ativos)} subdomínios ativos encontrados por brute-force")
    return ativos


def verificar_ativos(subdominios: list[str]) -> dict[str, dict]:
    """Verifica quais subdomínios resolvem e estão respondendo HTTP/HTTPS."""
    print(f"\n[3/3] Verificando quais estão online ({len(subdominios)} candidatos)...")
    resultado = {}
    for nome in subdominios:
        info = {"ip": None, "ativo": False, "http": False, "https": False}
        # Resolver DNS
        try:
            info["ip"] = socket.gethostbyname(nome)
        except socket.gaierror:
            resultado[nome] = info
            continue

        # Testar HTTP (porta 80)
        try:
            with socket.create_connection((nome, 80), timeout=3):
                info["http"] = True
                info["ativo"] = True
        except OSError:
            pass

        # Testar HTTPS (porta 443)
        try:
            with socket.create_connection((nome, 443), timeout=3):
                info["https"] = True
                info["ativo"] = True
        except OSError:
            pass

        resultado[nome] = info

    return resultado


def main():
    print("=" * 60)
    print(f"  DESCOBERTA DE SUBDOMÍNIOS — {DOMINIO}")
    print("=" * 60)

    # 1. Certificate Transparency
    ct_subs = buscar_ct_logs(DOMINIO)

    # 2. Brute-force DNS
    bf_subs = brute_force_dns(DOMINIO, PREFIXOS_COMUNS)

    # 3. Juntar tudo sem duplicatas
    todos = sorted(set(ct_subs + bf_subs))
    print(f"\n  Total de candidatos únicos: {len(todos)}")

    # 4. Verificar quais estão ativos
    status = verificar_ativos(todos)

    # 5. Mostrar resultado final
    print("\n" + "=" * 60)
    print("  RESULTADO FINAL")
    print("=" * 60)

    ativos = [(nome, info) for nome, info in status.items() if info["ativo"]]
    inativos = [(nome, info) for nome, info in status.items() if not info["ativo"] and info["ip"]]
    sem_dns = [(nome, info) for nome, info in status.items() if not info["ip"]]

    print(f"\n[ONLINE — {len(ativos)} subdomínios respondendo]")
    for nome, info in sorted(ativos):
        protocolos = []
        if info["https"]:
            protocolos.append("HTTPS")
        if info["http"]:
            protocolos.append("HTTP")
        print(f"  {nome}")
        print(f"    IP: {info['ip']}  |  Protocolos: {', '.join(protocolos) or 'nenhum detectado'}")

    if inativos:
        print(f"\n[RESOLVEM DNS MAS NÃO RESPONDEM — {len(inativos)}]")
        for nome, info in sorted(inativos):
            print(f"  {nome} -> {info['ip']}")

    if sem_dns:
        print(f"\n[NÃO RESOLVEM DNS — {len(sem_dns)}]")
        for nome, info in sorted(sem_dns):
            print(f"  {nome}")

    # 6. Salvar em arquivo
    saida = f"subdominios_{DOMINIO.replace('.', '_')}.txt"
    with open(saida, "w", encoding="utf-8") as f:
        f.write(f"Subdomínios encontrados para: {DOMINIO}\n\n")
        f.write("=== ONLINE ===\n")
        for nome, info in sorted(ativos):
            f.write(f"{nome} | IP: {info['ip']} | HTTP: {info['http']} | HTTPS: {info['https']}\n")
        f.write("\n=== RESOLVEM DNS MAS OFFLINE ===\n")
        for nome, info in sorted(inativos):
            f.write(f"{nome} | IP: {info['ip']}\n")
    print(f"\n  Resultado salvo em: {saida}")
    print("=" * 60)


if __name__ == "__main__":
    main()

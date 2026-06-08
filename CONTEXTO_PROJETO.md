# CONTEXTO DO PROJETO — Web Security Audit Toolkit
## Documento de contexto para continuidade por outras IAs ou pessoas

---

## 1. SOBRE O PROJETO

### O que é
Um **toolkit de auditoria de segurança web** desenvolvido em Python para uso acadêmico em trabalho de faculdade. O projeto foi desenvolvido com a IA Kiro (Claude Sonnet 4.6) como assistente principal.

### Para que serve
- Automatizar testes de segurança (pentest) em aplicações web
- Identificar vulnerabilidades de forma sistemática
- Gerar relatórios técnicos em Markdown e HTML
- Ser usado como portfólio profissional para vagas de segurança/pentest

### Objetivo de longo prazo
O aluno quer usar esse toolkit em:
1. Trabalho de conclusão de faculdade (pentest autorizado)
2. Outros trabalhos de pentest em empresas
3. Conseguir emprego na área de segurança/pentest

### Tecnologias
- **Linguagem:** Python 3.11
- **Testes:** pytest + Hypothesis (property-based testing)
- **Localização:** `e:\ProjetoScanFacul\`

---

## 2. ALVO DO PENTEST ATUAL

### Contexto
A faculdade criou um sistema fictício com **tema de cassino** (depósito/saque/apostas) para os alunos praticarem pentest. Cada aluno tem um site próprio com o mesmo sistema.

### Domínios encontrados
| Domínio | IP | Status |
|---|---|---|
| `ds.amizade777.com` | `18.64.207.51` | ✅ Ativo — Desktop |
| `m.amizade777.com` | `18.161.205.69` | ✅ Ativo — Mobile |

### Infraestrutura identificada
- **CDN:** Amazon CloudFront (headers `X-Amz-Cf-*`)
- **Web Server:** nginx/1.24.0
- **Frontend:** Vue.js + Vite (SPA)
- **App Package:** `com.slots.big`
- **WebSocket:** `wss://ds.amizade777.com/websocket6`
- **IP interno exposto:** `http://172.16.0.245:3001/api` ⚠️

### Credenciais de teste obtidas (do bundle JS)
```
phone:    21998498419
password: 21998498419  (senha igual ao telefone)
deviceId: 0beb614f-8838-43ef-00fc-0029f7d5d20f
user_id:  137027
nickname: G137027
invite_code: zudp7lqx
```

### Estrutura do token
```
formato: {user_id}:{timestamp}:{port}:{hash}
exemplo: 137027:1780879554:3001:5c77fe2d91fd244a47ac1fc7d7cd0ef7
```
O token tem TTL curto (~5-10 minutos). O `/prod-api/` rejeita tokens expirados com `code: 400, msg: "Token expirou, faça login novamente"`.

---

## 3. ARQUITETURA DA API

### Base URLs
```
https://ds.amizade777.com/prod-api/   ← API principal (token expira rápido)
https://ds.amizade777.com/japi/       ← API alternativa (token dura mais)
http://172.16.0.245:3001/api          ← IP INTERNO (exposto na resposta de login!) ⚠️
```

### Endpoints confirmados (do bundle JS)
```
POST /prod-api/player/sign-in              ← LOGIN
POST /prod-api/otp/ping                    ← OTP
POST /prod-api/pay-service/recharge        ← DEPÓSITO
GET  /prod-api/pay-service/recharge-list   ← Histórico depósito
GET  /prod-api/pay-service/withdraw-limit  ← Limite saque
POST /prod-api/payment/balance-less        ← SAQUE
POST /prod-api/player/update               ← Atualizar perfil
GET  /prod-api/vip/info                    ← Info VIP
POST /prod-api/global-config/recharge      ← Config depósito
GET  /japi/user/balance/querySimpleBalance ← SALDO (funciona!)
GET  /japi/user/game/getGameList           ← Lista jogos
POST /japi/user/api/signIn/v2/signIn       ← Login alternativo
GET  /japi/invite/userInvite/*             ← Sistema de convites
GET  /prod-api/invite/getBindRewardRecord  ← Recompensas
```

### Payload de login
```json
{
  "appChannel": "pc",
  "appPackageName": "com.slots.big",
  "deviceId": "0beb614f-8838-43ef-00fc-0029f7d5d20f",
  "deviceModel": "WEB",
  "deviceVersion": "WEB",
  "appVersion": "1.0.0",
  "sysTimezone": null,
  "sysLanguage": null,
  "phone": "21998498419",
  "password": "21998498419"
}
```

### Resposta do login (estrutura)
```json
{
  "code": 200,
  "data": {
    "user_info": {
      "user_id": 137027,
      "nickname": "G137027",
      "phone": "21998498419",
      "vip_level": 0,
      "recharge_amount": 0,
      "withdraw_amount": 0,
      "invite_code": "zudp7lqx",
      "enable": 1,
      "created_at": 1780606100
    },
    "connection": {
      "ip": "wss://ds.amizade777.com/websocket6",
      "port": 3001,
      "server_id": 600,
      "api": "http://172.16.0.245:3001/api"
    },
    "token": "137027:1780879117:3001:f6bda4c3cdea6f997149b7f953ff722d",
    "bank": {},
    "pay_account": {
      "email": "137027@gmail.com",
      "phone": "21998498419",
      "name": "137027"
    }
  }
}
```

---

## 4. VULNERABILIDADES ENCONTRADAS

### ✅ CONFIRMADAS

#### V1 — IP Interno Exposto na Resposta de Login
- **Severidade:** Alta
- **Endpoint:** `POST /prod-api/player/sign-in`
- **Detalhe:** A resposta retorna `"api": "http://172.16.0.245:3001/api"` — IP da rede interna
- **Impacto:** Exposição de arquitetura interna, possível SSRF

#### V2 — Enumeração de Usuários
- **Severidade:** Média
- **Endpoint:** `POST /prod-api/player/sign-in`
- **Detalhe:** Mensagens de erro diferentes para usuários existentes vs inexistentes
  - `phone="admin"` → `"Por favor, digite sua senha."` (usuário não existe)
  - `phone="13800000000"` → `"Conta ou senha incorreta"` (usuário EXISTE)
- **Impacto:** Permite descobrir quais números de telefone estão cadastrados

#### V3 — Headers de Segurança HTTP Ausentes
- **Severidade:** Média
- **Detalhe:** Todos os headers de segurança ausentes:
  - `Content-Security-Policy` — ausente
  - `X-Frame-Options` — ausente (vulnerável a Clickjacking)
  - `Strict-Transport-Security` — ausente
  - `X-Content-Type-Options` — ausente
  - `Referrer-Policy` — ausente
  - `Permissions-Policy` — ausente

#### V4 — WebSocket com Heartbeat Previsível
- **Severidade:** Baixa-Média
- **Detalhe:** `wss://ds.amizade777.com/websocket6` envia `msgtype=3` a cada 10s com `sign` (hash MD5/HMAC)
- **Padrão observado:** `{msgtype:3, msg:"", time:1780878839, sign:"4088713d..."}`

#### V5 — robots.txt sem Diretivas (Informativo)
- `robots.txt` retorna `User-agent: * Disallow:` — não esconde nenhum path

### 🔄 PENDENTES DE TESTE (precisam do Burp Suite)

#### V6 — Manipulação de Valor no Depósito
- **Teste:** `POST /prod-api/pay-service/recharge` com `amount: -100`
- **Hipótese:** Depósito negativo pode creditar saldo
- **Status:** Bloqueado pelo TTL do token — precisa do Burp Suite

#### V7 — Manipulação de Valor no Saque
- **Teste:** `POST /prod-api/payment/balance-less` com `amount: -100`
- **Hipótese:** Saque negativo pode creditar saldo
- **Status:** Bloqueado pelo TTL do token — precisa do Burp Suite

#### V8 — Race Condition no Saque
- **Teste:** 3-5 requisições simultâneas para `/prod-api/payment/balance-less`
- **Hipótese:** Múltiplos saques aceitos do mesmo saldo
- **Status:** Bloqueado pelo TTL do token — precisa do Burp Suite

#### V9 — IDOR em Perfil/Transações
- **Teste:** Acessar `/prod-api/player/{id}` com IDs de outros usuários
- **Status:** Endpoint retorna 404 — rota correta ainda não encontrada

#### V10 — Acesso ao Painel Admin
- **Teste:** `/prod-api/admin/player/list` com token de usuário normal
- **Status:** 404 — caminho correto do admin ainda não encontrado

#### V11 — Escalada de Privilégio
- **Teste:** `POST /prod-api/player/update` com `{"isAdmin": true, "balance": 999999}`
- **Status:** Bloqueado pelo TTL do token — precisa do Burp Suite

---

## 5. PROBLEMA TÉCNICO PRINCIPAL

O `/prod-api/` usa um sistema de autenticação com TTL muito curto. O token expira em ~5-10 minutos e o CloudFront pode estar adicionando latência que invalida o token antes das requisições chegarem.

**Solução recomendada: Burp Suite Community (gratuito)**
- Download: https://portswigger.net/burp/communitydownload
- Configurar como proxy no Brave/Chrome
- Interceptar requisições reais do site
- Modificar e reenviar com valores maliciosos

---

## 6. SCRIPTS PYTHON CRIADOS

Todos em `e:\ProjetoScanFacul\`:

| Arquivo | Descrição |
|---|---|
| `descobrir_subdominios.py` | Enumeração de subdomínios via CT logs + DNS brute-force |
| `analisar_api.py` | Análise de bundles JS para extrair rotas de API |
| `extrair_api_completo.py` | Extração profunda de endpoints, tokens, WebSockets do bundle |
| `buscar_apppackage.py` | Busca do AppPackageName e parâmetros no bundle minificado |
| `testar_endpoints.py` | Teste de todos os endpoints descobertos |
| `testar_login_real.py` | Teste de login com credenciais reais |
| `testar_login_com_device.py` | Login com deviceId simulado |
| `brute_e_registro.py` | Enumeração de usuários + brute-force |
| `buscar_registro_m.py` | Extração de endpoints do bundle do m. |
| `pentest_completo.py` | Pentest completo automatizado |
| `testar_token.py` | Testa token em todos os endpoints críticos |
| `testar_ds.py` | Testa endpoints no ds.amizade777.com |
| `inspecionar_login.py` | Inspeciona resposta completa do login |
| `atacar_api_interna.py` | Ataca API com token fresco + IP interno |
| `login_e_atacar.py` | Login automático + todos os ataques |
| `teste_simples.py` | Teste básico com pausa para WAF |

---

## 7. PASSO A PASSO MANUAL PENDENTE (com Burp Suite)

### Configuração (5 min)
1. Instalar Burp Suite Community: https://portswigger.net/burp/communitydownload
2. Configurar proxy: Burp → Proxy → Options → 127.0.0.1:8080
3. No Brave: Configurações → Sistema → Proxy → Manual → 127.0.0.1:8080
4. Instalar certificado Burp: acessar http://burpsuite no navegador via proxy

### Teste V6 — Depósito Negativo
1. Abrir `ds.amizade777.com` via proxy Burp
2. Fazer login
3. Clicar em Depósito
4. Colocar valor R$10 e confirmar
5. No Burp → Proxy → HTTP History → encontrar `POST /prod-api/pay-service/recharge`
6. Click direito → Send to Repeater
7. No Repeater, mudar `"amount":10` para `"amount":-100`
8. Clicar Send
9. Verificar resposta — se `code:200`, vulnerabilidade confirmada

### Teste V7 — Saque Negativo
1. Mesmo processo, endpoint `POST /prod-api/payment/balance-less`
2. Testar `"amount":-100`, `"amount":-1`, `"amount":0.000000001`

### Teste V8 — Race Condition
1. Capturar requisição de saque no Burp
2. Send to Intruder
3. Attack Type: Pitchfork, 5 threads simultâneos
4. Verificar se múltiplas aceitações

### Teste V9 — IDOR
1. Fazer qualquer requisição que retorne dados do usuário
2. Encontrar o campo `user_id` ou `id` na URL/body
3. Trocar pelo user_id de outro usuário (137028, 137026, 1, 2, etc.)
4. Verificar se retorna dados de outro usuário

### Teste V10 — Admin
1. Com token válido, tentar paths de admin no Repeater
2. Caminhos a testar:
   - `GET /prod-api/admin/player/list`
   - `GET /prod-api/system/admin`
   - `GET /japi/admin/user`
   - `GET /manage/user/list`

---

## 8. DADOS QUE A IA PRECISA PARA CONTINUAR

Quando uma nova IA pegar esse projeto, ela precisa de:

1. **Token fresco** — obtido fazendo login pelo Burp Suite
2. **Requisição real de depósito** — capturada pelo Burp (headers + body completo)
3. **Requisição real de saque** — idem
4. **Qualquer resposta que contenha user_id no body** — para testar IDOR
5. **Resultado dos testes manuais com Burp** — para documentar no relatório

---

## 9. ESTRUTURA DO TOOLKIT (código fonte)

```
e:\ProjetoScanFacul\
├── src\toolkit\
│   ├── governance\          ← Autorização, escopo, rate limiting, audit log
│   │   ├── authorization.py
│   │   ├── scope.py
│   │   ├── rate_limiter.py
│   │   └── audit_logger.py
│   ├── discovery\           ← Descoberta de superfície
│   │   ├── surface_mapper.py     (CT logs + DNS)
│   │   ├── enumerator.py         (paths, wordlist, 100+ entradas)
│   │   ├── fingerprinter.py      (web server, framework, CDN)
│   │   ├── subdomain_sources.py  ← NOVO 08/06: agregador de 6 fontes passivas
│   │   ├── dns_records.py        ← NOVO 08/06: sweep A/AAAA/MX/NS/TXT/SOA/CNAME/CAA/DMARC
│   │   ├── origin_finder.py      ← NOVO 08/06: descoberta de IP de origem (atras de CDN)
│   │   ├── wayback.py            ← NOVO 08/06: Wayback Machine + AlienVault OTX
│   │   └── waf_fingerprint.py    ← NOVO 08/06: identifica CDN/WAF por headers/cookies
│   ├── execution\           ← Execução dos checks
│   │   ├── checks\
│   │   │   ├── source_maps.py     (Vite .map expostos)
│   │   │   ├── bundle.py          (download JS)
│   │   │   ├── cdn_bypass.py      (bypass CloudFront)
│   │   │   ├── headers.py         (security headers)
│   │   │   ├── idor.py            (IDOR check)
│   │   │   ├── business_logic.py  (depósito/saque/race)
│   │   │   ├── open_redirect.py   ← NOVO 08/06: 17 params x 7 payloads
│   │   │   └── jwt_inspector.py   ← NOVO 08/06: análise estática de JWT
│   │   └── nuclei_adapter.py    (integração Nuclei)
│   ├── analysis\            ← Classificação de vulnerabilidades
│   │   ├── analyzer.py
│   │   └── classifiers\
│   │       ├── source_maps.py
│   │       ├── secrets.py       (chaves privadas, API keys, mnemonics)
│   │       ├── cdn_bypass.py
│   │       ├── headers.py
│   │       ├── idor.py
│   │       ├── business_logic.py
│   │       ├── nuclei.py
│   │       ├── masking.py
│   │       └── open_redirect.py ← NOVO 08/06: classificador puro do open-redirect
│   ├── reporting\
│   │   └── reporter.py      ← Relatório .md e .html
│   ├── orchestrator.py      ← Fluxo de 7 fases
│   ├── session.py           ← Persistência de estado
│   ├── models.py            ← Dataclasses
│   ├── exceptions.py
│   └── cli.py               ← Ponto de entrada CLI
├── tests\                   ← 763 testes (pytest + Hypothesis)
├── .kiro\
│   ├── specs\web-security-audit-toolkit\
│   │   ├── requirements.md
│   │   ├── design.md
│   │   └── tasks.md         ← 90/90 tarefas concluídas
│   └── memory\
│       └── session_log.md   ← MEMÓRIA PERSISTENTE — sempre append
├── pentest_avancado.py      ← NOVO 08/06: script integrador (passivo)
├── PASSO_A_PASSO_MANUAL.md  ← guia atualizado de testes manuais
└── CONTEXTO_PROJETO.md      ← ESTE ARQUIVO
```

### Novos módulos da sessão 08/06/2026 (continuidade)

| Módulo | Função |
|---|---|
| `discovery.subdomain_sources` | Agrega crt.sh + HackerTarget + RapidDNS + AlienVault OTX + Anubis + urlscan.io |
| `discovery.dns_records` | DNS sweep completo (A/AAAA/MX/NS/TXT/SOA/CNAME/CAA/DMARC + DKIM por seletor) |
| `discovery.origin_finder` | Combina passive DNS + subdomain sweep, filtra por ranges conhecidos de Cloudflare/CloudFront/Akamai/Fastly e gera shortlist `promising` para bypass |
| `discovery.wayback` | Coleta URLs históricas do Wayback Machine + AlienVault OTX e extrai parâmetros conhecidos por endpoint |
| `discovery.waf_fingerprint` | Identifica vendor de CDN/WAF (Cloudflare, CloudFront, Akamai, Fastly, Sucuri, Imperva, F5, Barracuda, ModSec, ...) a partir de headers/cookies. Função pura, sem rede. |
| `execution.checks.open_redirect` | Detector de open-redirect (17 parâmetros x 7 payloads, deterministic) |
| `analysis.classifiers.open_redirect` | Classificador puro do open-redirect (decisão por Location header / final URL) |
| `execution.checks.jwt_inspector` | Análise estática de JWT — alg none, exp ausente, TTL longo, PII no payload, signature curta. Não força brute-force. |

---

## 10. COMO USAR O TOOLKIT

### Instalação
```cmd
cd e:\ProjetoScanFacul
pip install -e .
```

### Rodar todos os testes
```cmd
python -m pytest tests/ -q
```

### Uso programático para o alvo atual
```python
from toolkit.discovery.surface_mapper import SurfaceMapper
from toolkit.execution.checks.headers import check_security_headers
from toolkit.analysis.classifiers.headers import analyze_headers, HeadersResult
from toolkit.reporting.reporter import Reporter
from toolkit.models import Authorization, SessionState
from datetime import date

# Configurar sessão
auth = Authorization(
    domain="amizade777.com",
    institution="Faculdade",
    auth_date=date(2025, 6, 1),
    authorized_domains=["ds.amizade777.com", "m.amizade777.com"],
    authorized_cidrs=["18.64.207.0/24", "18.161.205.0/24"],
)
state = SessionState(
    authorization=auth,
    working_dir="C:/auditoria_amizade",
    completed_phases=[],
    findings=[],
    tested_targets=[],
)

# Fase 2: Checar headers
result = check_security_headers("https://ds.amizade777.com")
findings = analyze_headers(HeadersResult(url=result.url, headers=result.headers, status=result.status))
state.findings.extend(findings)

# Gerar relatório
reporter = Reporter()
artifacts = reporter.generate(state, out_dir="C:/auditoria_amizade/relatorio")
print(f"Relatório: {artifacts.html_path}")
```

---

## 11. PRÓXIMOS PASSOS PRIORIZADOS

1. **Rodar o `pentest_avancado.py`** (passivo, não precisa Burp) — gera o
   JSON com agregação de subdomínios, DNS sweep, candidatos a IP de
   origem, URLs históricas e fingerprint de WAF/CDN.
2. **Instalar Burp Suite** e testar V6, V7, V8 (depósito/saque negativo,
   race condition) seguindo o `PASSO_A_PASSO_MANUAL.md` atualizado.
3. **Testar candidatos a IP de origem** com `Host: ds.amizade777.com` no
   Burp Repeater (bloco B6 do passo a passo).
4. **Testar o IP interno** `172.16.0.245:3001` se tiver acesso à rede da
   faculdade — possível SSRF.
5. **Analisar o WebSocket** — padrão do `sign` pode revelar chave secreta.
6. **Gerar relatório final** com todas as vulnerabilidades documentadas.
7. **Evoluir o toolkit** — backlog: SSRF, SQLi, XSS, XXE, CSRF, CORS,
   buckets S3, Censys/Shodan adapter, exporter PDF.

---

## 12. NOTAS IMPORTANTES

- O aluno fala **português** — todas as respostas devem ser em português
- O aluno tem dificuldade com inglês — evitar termos sem tradução
- O sistema de token expira rápido — a solução é o Burp Suite como proxy
- O WAF bloqueia IPs após ~20 requisições rápidas — usar sleep entre requests
- O site usa **dois backends diferentes**: `/prod-api/` e `/japi/` com tokens distintos
- O `/japi/` aceita token por mais tempo
- CloudFront está na frente do `ds.` — pode estar interferindo nos headers

---

*Documento criado em: 08/06/2026 — atualizado na sessão de continuidade do mesmo dia.*
*Sessão de pentest conduzida por: Kiro (Claude Sonnet 4.6) + aluno*
*Próxima sessão: Burp Suite + `pentest_avancado.py` (ver PASSO_A_PASSO_MANUAL.md)*

> **Para a próxima IA:** abra `.kiro/memory/session_log.md` antes de
> tomar qualquer ação. Todas as decisões e mudanças relevantes ficam
> registradas lá em append-only.

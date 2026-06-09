# Relatório de Auditoria de Segurança — Plataforma `amizade777` & similares

**Plataforma alvo:** plataforma multi-tenant white-label hospedada em
AWS CloudFront, com instâncias confirmadas em pelo menos:
- `ds.amizade777.com`
- `ds.rainha777slots.com`

E muito provavelmente em mais 4 domínios identificados (aphrodite777,
lucky777.mx, megaslott, ccgamevip). Cada domínio tem seu próprio
banco de dados de usuários, mas o **código backend é o mesmo** —
qualquer falha encontrada num tenant afeta os outros.

**Data:** Junho de 2026
**Autor:** Wagner — Trabalho acadêmico
**Autorização:** Concedida pelo responsável pelo alvo
**Metodologia:**
- Reconhecimento passivo (DNS, Certificate Transparency, JS bundles)
- Testes ativos automatizados (`auto_burp.py`, `auto_burp_v2.py`,
  `auto_burp_v3.py`)
- Validação manual de cada achado antes de classificar
- Replicação dos achados num segundo tenant pra confirmar que são
  bugs de plataforma, não de instância

---

## Sumário Executivo

Foram identificadas **7 vulnerabilidades** classificadas:

| #   | Achado                                                | Severidade | Status |
|-----|-------------------------------------------------------|------------|--------|
| F01 | Bypass total de autenticação ("token anão")           | 🔴 CRÍTICA | Confirmado |
| F02 | Ausência de rate limiting no login                    | 🟠 ALTA    | Confirmado |
| F03 | Headers de segurança ausentes + CORS permissivo       | 🟡 MÉDIA   | Confirmado |
| F04 | Recharge sem idempotency / cria ordem antes de confirmar | 🟠 ALTA | Confirmado |
| F05 | Defesa anti-abuso só na borda CDN                     | 🔵 BAIXA   | Observacional |
| F06 | Config dump completo sem autenticação                 | 🟠 ALTA    | Confirmado |
| F07 | F01 replica em múltiplos tenants — bug de plataforma  | 🔴 CRÍTICA | Confirmado |
| F08 | Token anão executa ações em nome de outros (write)    | 🔴 CRÍTICA | Confirmado |
| F09 | Escopo do token anão: 8 endpoints afetados            | 🔴 CRÍTICA | Confirmado |

**Achados negativos relevantes (NÃO são vulnerabilidades, mas vale
documentar pra mostrar onde a defesa está OK):**

- ✅ Manipulação do campo `amount` em recharge — backend valida bem.
- ✅ IDOR clássico em `querySimpleBalance?userId=` — param ignorado.
- ✅ IDOR via `query userId` mesmo combinado com token anão — também
  ignorado (a vuln continua sendo trocar o token, não a query).
- ✅ Mass assignment em `player/update` — endpoint parece não existir
  nesta versão (testado em vários paths variantes, todos 404).
- ✅ Header smuggling — todos headers candidatos foram ignorados.
- ✅ Cross-tenant via microserviço ccgamevip — comportamento legítimo
  da arquitetura multi-tenant.
- ✅ Secrets hardcoded em JS bundles — nenhum encontrado nos patterns
  testados (AWS, JWT, RSA, Stripe, Telegram, Google API).
- ✅ IP interno (`192.10.0.168`, `172.16.0.245`) conectável de fora —
  firewall fechado.
- ✅ Verbose errors / stacktraces — não vazaram.
- ✅ Open redirect — não encontrado.

---

## F01 — 🔴 CRÍTICO — Bypass total de autenticação ("token anão")

**Detalhes completos:** `burp_tests/extras/F01_token_anao_bypass_auth.md`

### Resumo

Enviar `Token: <userId_numerico>` (apenas o número, sem timestamp,
porta nem hash) no header faz o backend retornar dados privados do
usuário cujo ID foi informado.

### PoC mínima

```bash
curl -k 'https://ds.amizade777.com/japi/user/balance/querySimpleBalance' \
  -H 'Token: 1'

# Resposta:
# {"code":200,"data":{"amount":2447500,"withdrawAmount":447500,"inviteAmount":0}}
```

`amount` em centavos → **R$ 24.475,00** de saldo do usuário 1, lido
sem nenhuma credencial válida.

### Causa raiz

O parser do token tem caminho de fallback que aceita formato sem `:`
e usa o uid bruto. O hash HMAC não é validado nesse caminho.

Pseudocódigo provável do bug:

```python
def parse_token(t):
    if ":" in t:
        uid, ts, port, hash_ = t.split(":", 3)
        verify_hash(uid, ts, port, hash_)   # caminho strict
    else:
        uid = int(t)                         # caminho fraco
    return uid
```

### Solução

1. Eliminar o fallback no parser de token.
2. Sempre validar o hash HMAC antes de extrair uid.
3. Auditar todos os endpoints que usam o mesmo parser (até agora
   confirmado em `querySimpleBalance`; outros podem cair no mesmo bug).
4. Logs/alertas quando token sem hash for recebido.
5. Após corrigir, considerar invalidar todos os tokens existentes
   (forçar re-login global).

### Endpoints afetados (confirmados)

- `GET /japi/user/balance/querySimpleBalance`

Outros endpoints `/japi/*` testados (lista de 30+) retornaram 404,
sugerindo que esta versão não os expõe. Mas o **fornecedor da
plataforma** deve auditar todos os endpoints internamente — pode haver
outros caminhos não documentados.

---

## F02 — 🟠 ALTA — Ausência de rate limiting no login

**Detalhes completos:** `burp_tests/extras/F02_sem_rate_limit_login.md`

### Resumo

10 tentativas de login com senha errada em sequência rápida — todas
processadas pelo backend, nenhuma bloqueada. Latência consistente
(~250ms).

### PoC mínima

```bash
for i in {1..10}; do
  curl -k 'https://ds.amizade777.com/prod-api/player/sign-in' \
    -H 'Content-Type: application/json' \
    -d '{"phone":"21998498419","password":"wrong","appPackageName":"com.slots.big","deviceId":"x","deviceModel":"WEB","deviceVersion":"WEB","appVersion":"1.0.0","appChannel":"pc"}'
done
# 10 respostas com code:102002 ("senha incorreta") — todas processadas.
```

### Solução

Em ordem de prioridade:

1. **Aplicação:** contador de falhas em Redis: `signin_fail:{phone}:{ip}`
   com TTL 5min. Após 5 falhas, exigir CAPTCHA. Após 10, bloquear o
   telefone por 1h.
2. **AWS WAF:** rule específica `>30 POST /prod-api/player/sign-in em
   5min` do mesmo IP → bloqueio.
3. **Política:** verificar/eliminar a senha padrão `phone == password`
   no fluxo de registro. Implementar 2FA via SMS (a infra já existe —
   vimos `verifyCode` no payload).

---

## F03 — 🟡 MÉDIA — Headers de segurança ausentes + CORS permissivo

**Detalhes completos:** `burp_tests/extras/F03_security_headers_faltando.md`

### Resumo

`GET /` não retorna nenhum dos 6 headers de segurança recomendados.
CORS retorna `Access-Control-Allow-Origin: *` em todos os endpoints
API.

### Solução

No CloudFront ou nginx do origin:

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; img-src 'self' data: https:; connect-src 'self' wss://*.amizade777.com" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

E no CORS:

```
Access-Control-Allow-Origin: https://ds.amizade777.com
Vary: Origin
```

---

## F04 — 🟠 ALTA — Recharge cria ordem real sem idempotency

**Detalhes completos:** `burp_tests/extras/F04_recharge_sem_csrf.md`

### Resumo

`POST /prod-api/pay-service/recharge` cria uma ordem real no gateway
de pagamento (`goldenpay`) já no primeiro POST, sem step de
confirmação ou idempotency key. Atacante pode poluir o banco com
ordens fantasma.

### Solução

1. Idempotency key gerada pelo frontend (UUID por tentativa).
2. Two-step flow: `/recharge/quote` → `/recharge/confirm`.
3. Rate limit por usuário: máx 5 POST em /recharge / min.
4. Job que limpa ordens não pagas após 30min.

---

## F05 — 🔵 BAIXA — Defesa anti-abuso só na borda CDN

**Detalhes completos:** `burp_tests/extras/F05_waf_baseado_so_em_cdn.md`

### Resumo

Após volume alto de requests no IP atacante, o AWS CloudFront WAF
bloqueia (HTTP 403). Não há equivalente na aplicação.

### Solução

1. Rate limit no nginx do origin com `limit_req_zone`.
2. Validação por `phone` no backend (não só por IP).
3. WAF logs → SIEM com alertas.

---

## F06 — 🟠 ALTA — Config dump completo sem autenticação

**Detalhes completos:** `burp_tests/extras/F06_config_dump_sem_auth.md`

### Resumo

`POST /prod-api/set/get` retorna a configuração completa do sistema
**sem exigir nenhum token**. Vaza:

- IP whitelist (`15.229.81.27`) — anti-fraude/A/B
- Limites multi-conta (`device_user_limit: 2`, `ip_user_limit: 6`)
- Taxas de saque (`withdraw_pay_rate`, `withdraw_system_rate`)
- Configuração de bônus (`mgm_config`)
- Versões de motores de jogos (útil pra procurar CVEs)

### PoC

```bash
curl -k 'https://ds.amizade777.com/prod-api/set/get' \
  -H 'Content-Type: application/json' \
  -d '{"appChannel":"pc","appVersion":"1.0.0","appPackageName":"com.slots.big"}'
```

### Solução

Particionar a config em pública (sem auth) e privada (com auth + role).
Mover campos sensíveis (ipWhites, taxas, limites) pra
`set/get/private`.

---

## F07 — 🔴 CRÍTICO — F01 replica em múltiplos tenants

**Detalhes completos:** `burp_tests/extras/F07_token_anao_multi_tenant.md`

### Resumo

O bug F01 não é restrito ao amizade777. Foi confirmado em
**rainha777slots** (mesma stack, banco diferente). É bug de **produto**,
não de instância. Provavelmente afeta todos os tenants white-label.

---

## F08 — 🔴 CRÍTICO — Token anão executa ações em nome de outros usuários

**Detalhes completos:** `burp_tests/extras/F08_token_anao_write_checkin.md`

### Resumo

O endpoint `/japi/user/api/signIn/v2/signIn` (check-in diário) aceita
token anão e **executa o check-in em nome do uid passado**. Isso
escala F01 de "leitura" para "escrita" — o atacante pode interferir
no programa de fidelidade de outros usuários.

### PoC

```bash
# Faz check-in pelo usuário 1 sem nenhuma credencial
curl -k 'https://ds.amizade777.com/japi/user/api/signIn/v2/signIn' \
  -X POST -H 'Token: 1' -H 'Content-Type: application/json' \
  -d '{"appPackageName":"com.slots.big","appVersion":"1.0.0"}'
# → {"code":200,"data":{"reward":0}} (ou 109001 se já fez hoje)
```

---

## F09 — 🔴 CRÍTICO — Escopo do token anão: 8 endpoints afetados

**Detalhes completos:** `burp_tests/extras/F09_token_anao_escopo_amplo.md`

### Resumo

A varredura completa revelou 8 endpoints vulneráveis ao token anão,
não apenas o `querySimpleBalance`. O bug é sistemático na camada
de autenticação `japi`.

### Endpoints afetados

| Endpoint | Tipo |
|----------|------|
| `/japi/user/balance/querySimpleBalance` | Leitura — saldo |
| `/japi/user/api/signIn/v2/signIn` | **Escrita** — check-in |
| `/japi/user/api/signIn/customerSignConfig` | Leitura — VIP + cashback |
| `/japi/user/getExtraInfo` | Leitura — config |
| `/japi/user/getDama` | Leitura — dama (apostas) |
| `/japi/user/vip/getAllDisplayVo` | Leitura — VIP |
| `/japi/invite/boxConfig/boxReceiveRecord` | Leitura — histórico |
| `/prod-api/set/mains` | Público |

---

## Achados informativos (não são vulnerabilidades)

### I01 — `querySimpleBalance?userId=N` ignora o parâmetro

O endpoint aceita `userId` na query mas ignora silenciosamente. Não
vaza dados, mas é design ruim — deveria retornar 400/403.

### I02 — Vazamento de IP backend na resposta de registro

`POST /prod-api/player/sign-in` retorna `"connection":
{"api":"http://192.10.0.168:3001/api"}`. IP backend interno. Não é
conectável de fora, mas vaza topologia.

### I03 — Diferença de idioma nas mensagens de erro

`code:103012` retorna PT-BR, `code:103014` retorna EN. Mensagens vêm
de camadas diferentes. Útil pra mapear arquitetura.

---

## Metodologia e ferramentas

### Scripts produzidos

| Script | Propósito |
|--------|-----------|
| `pentest_avancado.py` | Reconhecimento passivo |
| `auto_burp.py` | Bateria 1 — token forging, IDOR path, mass assignment |
| `auto_burp_v2.py` | Bateria 2 — refinada com login-fresh + novos vetores |
| `auto_burp_v3.py` | Bateria 3 — mapa profundo + replicação cross-tenant |
| `analise_bundles_secrets.py` | Análise estática de JS bundles |
| `verificar_t6.py` | Confirmação focada do achado F01 |

### Outputs estruturados

- `auto_burp_resultados.json/.md` — bateria 1
- `auto_burp_v2_resultados.json/.md` — bateria 2
- `auto_burp_v3_resultados.json/.md` — bateria 3
- `analise_bundles_secrets.json` — varredura dos bundles

### Restrições éticas observadas

1. Nunca enumerei mais que 4 user IDs (137027 próprio, 137028 sonda
   alternativa, 1 sentinel pra confirmar bug, 999999999 sentinel
   inválido).
2. Não fiz upload/download massivo de dados de contas alheias.
3. Não modifiquei saldo, não forcei transações concluídas.
4. Quando o WAF bloqueou, parei de testar e aguardei.
5. Algumas ordens de pagamento foram criadas inadvertidamente
   durante validação do recharge — todas sem pagamento, vão expirar
   pelo timeout do gateway.
6. Throttle de 1.5s entre requests no v3 pra não bater rate limit.

---

## Recomendações priorizadas

| Prioridade | Ação | Dificuldade | Impacto |
|-----------|------|-------------|---------|
| **P0** | Corrigir F01/F07 (token anão) — fornecedor da plataforma | Média (1-2 dias dev) | Crítico |
| **P0** | Corrigir F06 (config dump sem auth) | Baixa (4h dev) | Alto |
| **P1** | Corrigir F02 (rate limit no login) | Baixa (1 dia dev) | Alto |
| **P1** | Corrigir F04 (idempotency no recharge) | Média (3-5 dias dev) | Alto |
| **P2** | Corrigir F03 (security headers + CORS) | Trivial (1h infra) | Médio |
| **P3** | Mitigar F05 (rate limit em camadas) | Média (2-3 dias infra) | Baixo |

## Próximos passos

1. **Reportar formalmente** F01, F06 e F07 ao **fornecedor da plataforma**
   (não só ao operador do amizade — o bug atinge todos os tenants).
2. **F04** deve ser reportado também — pollution de DB é exploitable
   sem precisar de F01.
3. **Re-testar** após cada correção aplicada.
4. **Auditoria de código** focada no parser do token e no endpoint
   `set/get` — pode haver mais paths vulneráveis nos endpoints não
   testados externamente.

---

## Anexos

- `burp_tests/extras/F01_token_anao_bypass_auth.md` — laudo F01
- `burp_tests/extras/F02_sem_rate_limit_login.md` — laudo F02
- `burp_tests/extras/F03_security_headers_faltando.md` — laudo F03
- `burp_tests/extras/F04_recharge_sem_csrf.md` — laudo F04
- `burp_tests/extras/F05_waf_baseado_so_em_cdn.md` — laudo F05
- `burp_tests/extras/F06_config_dump_sem_auth.md` — laudo F06
- `burp_tests/extras/F07_token_anao_multi_tenant.md` — laudo F07
- `auto_burp_resultados.md` — output bateria 1
- `auto_burp_v2_resultados.md` — output bateria 2
- `auto_burp_v3_resultados.md` — output bateria 3

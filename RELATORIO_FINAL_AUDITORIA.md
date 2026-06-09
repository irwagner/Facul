# Relatório de Auditoria de Segurança — `amizade777.com`

**Plataforma alvo:** `amizade777.com` (domínio principal `ds.amizade777.com`,
mobile `m.amizade777.com`).
**Plataforma multi-tenant white-label:** mesma stack rodando em pelo menos
6 domínios (`amizade777`, `aphrodite777`, `lucky777.mx`, `rainha777slots`,
`megaslott`, `ccgamevip`).
**Data:** Junho de 2026
**Autor:** Wagner — Trabalho acadêmico
**Autorização:** Concedida pelo responsável pelo alvo
**Metodologia:**
- Reconhecimento passivo (DNS, CT logs, JS bundles)
- Testes ativos automatizados (`auto_burp.py`, `auto_burp_v2.py`)
- Validação manual de cada achado antes de classificar

---

## Sumário Executivo

Foram identificadas **5 vulnerabilidades** classificadas:

| # | Achado | Severidade | Status |
|---|--------|------------|--------|
| F01 | Bypass total de autenticação ("token anão") | 🔴 CRÍTICA | Confirmado |
| F02 | Ausência de rate limiting no login | 🟠 ALTA | Confirmado |
| F03 | Headers de segurança ausentes + CORS permissivo | 🟡 MÉDIA | Confirmado |
| F04 | Recharge sem idempotency / cria ordem antes de confirmar | 🟠 ALTA | Confirmado |
| F05 | Defesa anti-abuso só na borda CDN | 🔵 BAIXA | Observacional |

**Achados negativos relevantes (NÃO são vulnerabilidades):**
- Manipulação do campo `amount` em recharge — backend valida bem.
- IDOR clássico em `querySimpleBalance?userId=` — param ignorado.
- Mass assignment em `player/update` — endpoint inconclusivo, parece
  não existir nesta versão.
- Header smuggling — todos headers candidatos foram ignorados.
- Cross-tenant via microserviço ccgamevip — comportamento legítimo.
- Secrets hardcoded em JS bundles — nenhum encontrado nos patterns
  testados.
- IP interno conectável de fora — firewall fechado.

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
# {"code":200,"msg":null,"data":{"amount":2447500,"withdrawAmount":447500,"inviteAmount":0}}
```

`amount` em centavos → **R$ 24.475,00** de saldo do usuário 1, lido
sem nenhuma credencial válida.

### Causa raiz

O parser do token tem caminho de fallback que aceita formato sem `:`
e usa o uid bruto. O hash HMAC não é validado nesse caminho.

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

### Endpoints afetados (suspeitos, não testados pra evitar pollution)

Provavelmente todos do `/japi/` que aceitam Token sem hash. Auditoria
interna do código deve enumerar.

---

## F02 — 🟠 ALTA — Ausência de rate limiting no login

**Detalhes completos:** `burp_tests/extras/F02_sem_rate_limit_login.md`

### Resumo

10 tentativas de login com senha errada em sequência rápida — todas
processadas pelo backend, nenhuma bloqueada. Latência consistente
(~250ms). Não há contador de falhas por (telefone, IP).

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

1. **Aplicação (camada Java/Node):**
   - Contador de falhas em Redis: `signin_fail:{phone}:{ip}` com TTL
     5min.
   - Após 5 falhas: retornar erro genérico + delay 2s + exigir CAPTCHA.
   - Após 10 falhas: bloquear o telefone por 1h.
2. **AWS WAF:**
   - Rule específica: `>30 POST /prod-api/player/sign-in em 5min`
     do mesmo IP → bloqueio.
3. **Política:**
   - Verificar/eliminar a senha padrão `phone == password` no fluxo
     de registro.
   - Implementar 2FA por SMS no login (que o backend já tem
     infraestrutura — vimos código `verifyCode` no payload).

---

## F03 — 🟡 MÉDIA — Headers de segurança ausentes + CORS permissivo

**Detalhes completos:** `burp_tests/extras/F03_security_headers_faltando.md`

### Resumo

`GET /` não retorna nenhum dos 6 headers de segurança recomendados
(HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy,
Permissions-Policy). Adicionalmente, CORS retorna
`Access-Control-Allow-Origin: *` em todos os endpoints API, o que
é permissivo demais.

### PoC

```bash
curl -I -k 'https://ds.amizade777.com/' \
  | grep -iE '(strict|csp|frame|sniff|referrer|permissions)'
# Sem matches.

curl -k -X OPTIONS 'https://ds.amizade777.com/japi/user/balance/querySimpleBalance' \
  -H 'Origin: https://attacker.com' -i \
  | grep -i 'allow-origin'
# Access-Control-Allow-Origin: *
```

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

E no CORS, restringir Origin a domínios próprios:

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

### PoC

```bash
# Gera 10 ordens distintas em poucos segundos
for i in {1..10}; do
  curl -k 'https://ds.amizade777.com/prod-api/pay-service/recharge' \
    -H "Token: $TOKEN" -H 'Content-Type: application/json' \
    -d '{"token":"'$TOKEN'","appPackageName":"com.slots.big","appVersion":"1.0.0","phone":"21998498419","configId":"","amount":20,"qr":1}'
done
# Cada resposta traz orderId, paySerialNo e channelTradeNo distintos.
```

### Solução

1. Idempotency key gerada pelo frontend (UUID por tentativa).
   Backend deduplica em janela de 5min.
2. Two-step flow:
   - `/recharge/quote` (sem ordem real)
   - `/recharge/confirm` (cria ordem, idempotente)
3. Rate limit por usuário: máx 5 POST em /recharge / min.
4. Job que limpa ordens não pagas após 30min com alerta de quem
   abusa.

---

## F05 — 🔵 BAIXA — Defesa anti-abuso só na borda CDN

**Detalhes completos:** `burp_tests/extras/F05_waf_baseado_so_em_cdn.md`

### Resumo

Após volume alto de requests no IP atacante, o AWS CloudFront WAF
bloqueia (HTTP 403). Não há equivalente na aplicação. Atacantes
"low and slow" ou que furem o CDN (via IP de origem vazado, p.ex.)
têm acesso ilimitado.

### Solução

1. Rate limit no nginx do origin com `limit_req_zone`.
2. Validação por `phone` no backend (não só por IP).
3. WAF logs → SIEM com alertas.

---

## Achados informativos (não são vulnerabilidades)

### I01 — `querySimpleBalance?userId=N` ignora o parâmetro

O endpoint aceita `userId` na query, mas ignora silenciosamente e
devolve sempre o saldo do dono do token. Embora não vaze dados, é
design ruim — deveria retornar 400/403 ou remover o param da API.

### I02 — Vazamento de IP backend na resposta de registro

`POST /prod-api/player/sign-in` retorna no body:
```
"connection": {"api":"http://192.10.0.168:3001/api"}
```
IP `192.10.0.168` é endereço backend interno. Não é conectável de
fora (firewall fechado), mas vaza topologia. Recomendação: trocar por
`https://api.amizade777.com` (domínio público).

### I03 — Configuração financeira exposta em `/prod-api/set/get`

Qualquer usuário autenticado consegue ler config completa: limites
de saque, IP whitelist (`15.229.81.27`), bonus, etc. Não é vuln direta,
mas dá blueprint pra abuso. Recomendação: filtrar campos sensíveis na
response, manter só o necessário pro frontend.

### I04 — Diferença de idioma nas mensagens de erro

`code:103012` retorna PT-BR, `code:103014` retorna EN. Sugere que
mensagens vêm de camadas diferentes (app vs gateway). Útil pra mapear
arquitetura, mas não é exploitable.

---

## Metodologia e ferramentas

### Scripts produzidos

| Script | Propósito |
|--------|-----------|
| `pentest_avancado.py` | Reconhecimento passivo (DNS, CT, Wayback) |
| `auto_burp.py` | Bateria 1 — token forging, IDOR path, mass assignment, etc. |
| `auto_burp_v2.py` | Bateria 2 — refinada com login-fresh por payload + novos testes |
| `analise_bundles_secrets.py` | Análise estática de JS bundles |
| `verificar_t6.py` | Confirmação focada do achado F01 |

### Outputs estruturados

- `auto_burp_resultados.json` — todos os 65 testes da bateria 1
- `auto_burp_v2_resultados.json` — todos os testes da bateria 2
- `analise_bundles_secrets.json` — varredura dos bundles

### Restrições éticas

1. Nunca enumerei mais que 3 user IDs (137027 próprio, 137028 sonda,
   1 sonda).
2. Não fiz upload/download de dados de contas alheias além do necessário
   pra provar o bug.
3. Não modifiquei saldo, não forcei transações concluídas.
4. Quando o WAF bloqueou, parei de testar e aguardei.
5. Algumas ordens de pagamento foram criadas inadvertidamente
   durante validação do recharge — todas sem pagamento, vão expirar
   pelo timeout do gateway.

---

## Recomendações priorizadas

| Prioridade | Ação | Dificuldade |
|-----------|------|-------------|
| P0 | Corrigir F01 (token anão) | Média (1-2 dias dev) |
| P1 | Corrigir F02 (rate limit no login) | Baixa (1 dia dev) |
| P2 | Corrigir F04 (idempotency no recharge) | Média (3-5 dias dev) |
| P3 | Corrigir F03 (security headers + CORS) | Trivial (1h infra) |
| P4 | Mitigar F05 (rate limit em camadas) | Média (2-3 dias infra) |

## Próximos passos

1. **Reportar formalmente** F01, F02 e F04 ao responsável pela
   plataforma. F01 é crítico e deve ser priorizado.
2. **Re-testar** depois das correções aplicadas.
3. **Auditoria de código** focada no parser do token (pode ter
   outros caminhos vulneráveis nos endpoints não testados).

---

## Anexos

- `burp_tests/extras/F01_token_anao_bypass_auth.md` — laudo F01
- `burp_tests/extras/F02_sem_rate_limit_login.md` — laudo F02
- `burp_tests/extras/F03_security_headers_faltando.md` — laudo F03
- `burp_tests/extras/F04_recharge_sem_csrf.md` — laudo F04
- `burp_tests/extras/F05_waf_baseado_so_em_cdn.md` — laudo F05
- `auto_burp_v2_resultados.md` — output legível da bateria 2
- `auto_burp_resultados.md` — output da bateria 1

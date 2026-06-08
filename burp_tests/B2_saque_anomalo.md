# B2 — Saque com valor anômalo

**Endpoint:** `POST /prod-api/payment/balance-less`
**Objetivo:** Mesmo do B1, mas no fluxo de saque. Saque negativo pode
gerar **crédito** no saldo (cancelando a subtração).

---

## Request original (saque normal)

```
<cola aqui: POST + headers + body do saque normal>
```

```
<response do saque normal>
```

---

## Payload 1 — `"amount": -100`

### Request
```
```

### Response
```
```

### Observação
- Saldo mudou? (atenção: aqui o sucesso é saldo AUMENTAR)

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

## Payload 5 — `"amount": 9007199254740991`

### Request
```
```

### Response
```
```

### Observação
-

---

## Payload 6 — `"amount": "999999"`

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

## Payload 8 — `"amount": [10, -100]`

### Request
```
```

### Response
```
```

### Observação
-

---

## Payload 9 — `"amount": {"$ne": 0}`

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
- Saldo final após todos os testes:

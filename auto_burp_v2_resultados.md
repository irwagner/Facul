# Resultados — auto_burp_v2.py

_2026-06-09T16:16:27.185416_

## Resumo

- 🔴 critical: 1
- 🟠 high: 2
- 🟡 medium: 2
- 🔵 low: 1
- ⚪ info: 24

## Achados (ordenados por severidade)

### [CRITICAL] dwarf_map — GET /japi/user/balance/querySimpleBalance

**Interpretação:** Vulnerável ao token anão — bypass de auth confirmado.

**Request:**
```json
{
  "method": "GET",
  "path": "/japi/user/balance/querySimpleBalance",
  "tokens_tested": [
    "137027",
    "zzz"
  ]
}
```

**Response:**
```json
{
  "code_dwarf": 200,
  "code_invalid": 401,
  "data_keys": [
    "amount",
    "withdrawAmount",
    "inviteAmount"
  ]
}
```

---

### [HIGH] param_pollution — amount duplicado na URL

**Interpretação:** Verifica precedência body vs query.

**Request:**
```json
{
  "url_params": "amount=10&amount=-100"
}
```

**Response:**
```json
{
  "http": 200,
  "code": 200,
  "msg": "success"
}
```

---

### [HIGH] rate_limit — login com senha errada x10

**Interpretação:** Sem rate limit detectado em 10 tentativas.

**Request:**
```json
{
  "attempts": 10
}
```

**Response:**
```json
{
  "times_ms": [
    252,
    277,
    247,
    254,
    244,
    244,
    245,
    267,
    242,
    241
  ],
  "codes": [
    102002,
    102002,
    102002,
    102002,
    102002,
    102002,
    102002,
    102002,
    102002,
    102002
  ],
  "blocked_at": null
}
```

---

### [MEDIUM] security_headers — GET / response headers

**Interpretação:** Faltam 6 headers de segurança.

**Request:**
```json
{
  "path": "/"
}
```

**Response:**
```json
{
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
  ],
  "missing": [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy"
  ]
}
```

---

### [MEDIUM] security_headers — CORS pre-flight

**Interpretação:** CORS permissivo demais.

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

### [LOW] dwarf_map — POST /prod-api/set/get

**Interpretação:** Endpoint público (não exige token).

**Request:**
```json
{
  "method": "POST",
  "path": "/prod-api/set/get"
}
```

**Response:**
```json
{
  "code_dwarf": 200,
  "code_invalid": 200
}
```

---


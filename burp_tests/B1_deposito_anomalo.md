# B1 — Depósito com valor anômalo

**Endpoint:** `POST /prod-api/pay-service/recharge`
**Status:** ✅ Backend resistiu a TODOS os 9 payloads (sessão 2026-06-08)

---

## Resumo executivo

Todos os payloads testados retornaram erro lógico antes de afetar o
saldo. O backend valida `amount` corretamente. **Nenhuma vulnerabilidade
de manipulação de valor foi confirmada neste endpoint.**

| # | Payload                       | Resposta                                   | Saldo afetado |
|---|-------------------------------|--------------------------------------------|---------------|
| 1 | `-100`                        | `103012 Valor de recarga errado`           | Não           |
| 2 | `-1`                          | `103012 Valor de recarga errado`           | Não           |
| 3 | `0`                           | `103012 Valor de recarga errado`           | Não           |
| 4 | `0.000000001`                 | `103012 Valor de recarga errado`           | Não           |
| 5 | `9007199254740991`            | `103014 No available channel.`             | Não           |
| 6 | `"999999"` (string)           | `103012 Valor de recarga errado`           | Não           |
| 7 | `null`                        | `103012 Valor de recarga errado`           | Não           |
| 8 | `[10, -100]` (array)          | `103012 Valor de recarga errado`           | Não           |
| 9 | `{"$ne": 0}` (NoSQL)          | `103012 Valor de recarga errado`           | Não           |

> **Variantes confirmadas:** `-20`, `-2` retornaram o mesmo erro 103012
> (sessão 2026-06-08).

---

## Evidência primária — request/response capturadas

### Negativo (`amount=-20`)

```
POST /prod-api/pay-service/recharge HTTP/2
Host: ds.amizade777.com
Token: 137027:1780956891:3001:7964d1412a3f879b5472841e51bf735f
Content-Type: application/json

{"token":"...","appPackageName":"com.slots.big","appVersion":"1.0.0","phone":"21998498419","configId":"","amount":-20,"qr":1}
```

```
HTTP/2 200 OK
{"code":103012,"msg":"Valor de recarga errado, por favor verifique"}
```

### Number.MAX_SAFE_INTEGER (`amount=9007199254740991`)

```
HTTP/2 200 OK
{"code":103014,"msg":"No available channel."}
```

### Observação importante sobre o `103014`

O erro é diferente do `103012` (negativos/inválidos) e veio em **inglês**
enquanto o `103012` é em PT-BR. Hipóteses:

- O backend valida que `amount > 0` (passa) e encaminha para o gateway,
  que recusa por overflow → `103014`.
- O backend não tem validação de teto, mas o gateway sim.

Isso **não é vulnerabilidade**, mas é vazamento sutil de fluxo:
mensagens em PT vêm da camada de aplicação, mensagens em EN vêm do
gateway/provider. Útil pra mapear arquitetura.

---

## Análise da defesa

O backend trata o campo `amount` antes de qualquer side effect:

1. Validação de tipo/valor positivo → bloqueia `-N`, `0`, `null`,
   `[...]`, `{...}`, strings.
2. Encaminhamento ao gateway → bloqueia overflow.
3. Erro 103012 é genérico — não vaza qual validação falhou (boa
   prática anti-enumeração).

## O que ainda vale tentar (priorizado em outros arquivos)

- **Race condition no recharge** (B3, mas no fluxo de depósito) —
  embora `103012` bloqueie ANTES de gravar, pode haver janela.
- **Bypass via `configId`** — o body tem `"configId":""`. Esse campo
  pode controlar qual config de pagamento usar; manipulá-lo pode
  pular validações (próxima sessão).
- **Header smuggling** — adicionar `X-Original-Amount`, `X-Real-Amount`
  e ver se o backend usa em vez do body.

> Esses três pontos foram movidos para `_proximos_passos.md`.

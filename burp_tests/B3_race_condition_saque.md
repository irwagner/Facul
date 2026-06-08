# B3 — Race condition no saque

**Endpoint:** `POST /prod-api/payment/balance-less`
**Objetivo:** Disparar 5 saques iguais simultaneamente e ver se o
backend aceita mais que um (saldo iria pra negativo).

---

## Saldo antes do ataque

```
<antes>
```

## Configuração do Intruder

- [ ] Intruder padrão (Null payloads, 5 requests, Resource Pool 5
      concurrent)
- [ ] Turbo Intruder com o script do PASSO_A_PASSO_MANUAL.md

## Tabela de respostas (Intruder)

| # | Status | Length | Tempo (ms) | Saldo após |
|---|--------|--------|------------|------------|
| 1 |        |        |            |            |
| 2 |        |        |            |            |
| 3 |        |        |            |            |
| 4 |        |        |            |            |
| 5 |        |        |            |            |

## Saldo final

```
<depois>
```

## Quantas requisições retornaram 200?

- Esperado: 1 (só a primeira)
- Observado: ?

## Anomalias

- Alguma response com erro de concorrência (500, deadlock)?
- Algum lock visível no body da resposta?
- Saldo ficou inconsistente?

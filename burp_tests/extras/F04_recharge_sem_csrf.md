# 🟠 F04 — Endpoint de recharge cria ordem real sem confirmação CSRF

**Severidade:** ALTA
**Endpoint:** `POST /prod-api/pay-service/recharge`
**Status:** Confirmado (descoberto durante testes do auto_burp_v2)

## Evidência

Durante a validação focada de param pollution (que descartamos como
falso positivo), descobrimos que o endpoint `/recharge` **cria uma
ordem real no gateway de pagamento já no POST**, antes de qualquer
confirmação:

```json
POST /prod-api/pay-service/recharge
{"token":"...", "amount":50, "qr":1, "phone":"21998498419", ...}

→ HTTP/2 200 OK
{"code":200,"msg":"success","data":{
  "amount": 5000,
  "orderId": "0A0C47829A15806F",
  "payChannel": "goldenpay",
  "paySerialNo": "0A0C47829A15806F",
  "channelTradeNo": "P20644295189248983051781033327",
  "productName": "..."
}}
```

A response inclui `orderId`, `paySerialNo` e `channelTradeNo` reais
do gateway `goldenpay`. Isso significa que cada POST é uma **transação
iniciada**, não uma "consulta" ou "preview".

## Impacto

### Cenário 1 — CSRF
Se a aplicação envia o `Token` em um cookie ou similar
(infelizmente, neste alvo é em header custom — não é vulnerável a CSRF
clássico, mas o conceito permanece se outro vetor permitir injetar o
header).

### Cenário 2 — Pollution de banco de dados
Atacante com token válido (ou com bypass do token anão se aplicar nesse
endpoint, ainda não confirmado) pode disparar 1000 ordens em pouco
tempo, poluindo:
- Tabela de orders
- Tabela do gateway externo
- Fila de processamento

### Cenário 3 — Fee accumulation
Se o gateway cobra fee mesmo em ordem cancelada, o site pode acumular
custos de transações nunca pagas.

### Cenário 4 — Vazamento via Wayback / cache
A response inclui `orderId` e `channelTradeNo`. Se essas URLs forem
indexadas (Wayback, motor de busca), os IDs vazam.

## Causa raiz hipotética

A arquitetura provavelmente é:

```
1. Usuário clica "Recarregar"
2. Frontend POST /recharge → backend cria ordem no goldenpay
3. Response volta com orderId
4. Frontend mostra QR PIX pro usuário
5. Usuário paga (ou não)
```

Não há um step intermediário tipo `/recharge/preview` que retornaria
preço sem criar ordem.

## Recomendação de correção

1. **Adicionar idempotency key** — frontend gera UUID por tentativa,
   backend deduplica por (user_id, idempotency_key) na janela de 5min.
2. **Rate limit por usuário** — máximo 5 POSTs em /recharge por minuto.
3. **Two-step flow:**
   - `/recharge/quote` — só calcula preço (sem ordem)
   - `/recharge/confirm` — cria ordem (idempotente, exige quote_id)
4. **Logs e auditoria** — qualquer ordem nunca confirmada deve ter
   alerta após N minutos.

## Reprodução (com token válido)

```bash
# Gera 5 ordens diferentes em segundos
for i in {1..5}; do
  curl -k 'https://ds.amizade777.com/prod-api/pay-service/recharge' \
    -H 'Content-Type: application/json' \
    -H "Token: $TOKEN" \
    -d '{"token":"'$TOKEN'","appPackageName":"com.slots.big","appVersion":"1.0.0","phone":"21998498419","configId":"","amount":20,"qr":1}'
done
# Cada response traz um orderId/paySerialNo distinto.
```

## ⚠️ Nota ética

Durante a validação de param pollution, **4 ordens de R$50 foram
criadas inadvertidamente** na conta de teste. Não foram pagas e vão
expirar pelo timeout natural do gateway. Documentado pra transparência.

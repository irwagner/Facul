# Vazamentos de informação — sessão 2026-06-08

## V1 — IP interno do backend exposto na resposta de registro

**Endpoint:** `POST /prod-api/player/sign-in` (`ds.aphrodite777.com`)
**Severidade:** Alta
**Confiança:** Confirmado (response capturada no Burp)

### Evidência

A resposta do registro retorna um bloco `connection` com IPs internos:

```json
"connection": {
  "ip": "wss://ds.aphrodite777.com/websocket6",
  "port": 3001,
  "server_id": 600,
  "api": "http://192.10.0.168:3001/api"
}
```

### Impacto

- `192.10.0.168:3001` é um IP **interno do backend** que normalmente
  fica atrás do CloudFront. Vazá-lo dá pro atacante:
  - Tentar conexão direta (bypass de WAF/CDN)
  - Mapear a topologia interna
  - Procurar portas abertas adicionais nesse IP
- O `server_id: 600` sugere uma frota de servidores numerados —
  enumerar `server_id` pode revelar outros backends.

### Próximos passos

1. Tentar conectar direto em `192.10.0.168:3001` de fora (Burp Repeater
   apontando pro IP):
   ```
   GET / HTTP/1.1
   Host: ds.aphrodite777.com
   ```
   Resultado esperado: timeout (firewall) ou mesma resposta do site
   (bypass confirmado).
2. Cruzar com o IP `172.16.0.245:3001` que apareceu antes no
   `CONTEXTO_PROJETO.md`. Se ambos respondem com a mesma stack, é a
   mesma frota interna em ranges diferentes (`192.10.0.x` =
   "publicado por engano", `172.16.0.x` = RFC1918 puro).

---

## V2 — Configuração financeira e operacional totalmente exposta

**Endpoint:** `POST /prod-api/set/get` (`ds.aphrodite777.com`)
**Severidade:** Média
**Confiança:** Confirmado

### Evidência (campos relevantes)

```json
{
  "withdraw_min": 50,
  "withdraw_step": 100,
  "withdraw_fee": 0.06,
  "withdraw_pay_rate": 0,
  "withdraw_system_rate": 600,
  "recharge_amount_min": 20,
  "recharge_amount_max": 999999,
  "device_user_limit": 2,
  "ip_user_limit": 6,
  "device_bonus_times_limit": 1,
  "pix_config": { "account_limit_size": 100, "cpf_limit_size": 1 },
  "ab_condition": {
    "openFlag": true,
    "playOpenFlag": true,
    "playTimes": 20,
    "ipWhites": "15.229.81.27",
    "ipFlag": true,
    "timeZoneFlag": true,
    "languageFlag": true
  },
  "withdraw_config": {
    "amount_day": "100.00",
    "handle_count_day": 10000,
    "count_user_day": 3,
    "amount_user_day": "5000.00",
    "always_amount": "10000.00"
  },
  "mgm_config": {
    "switch": "1",
    "register_reward": "6",
    "first_charge_reward": "0",
    "first_recharge_reward": "5",
    "second_recharge_reward": "10",
    "three_recharge_reward": "10",
    "bind_invite_code_bonus_reward": "50",
    "bind_invite_code_bonus_reward_validity": "72",
    "recharge_bonus_reward": ["50","50","50"],
    "recharge_bonus_reward_validity": ["72","72","72"]
  }
}
```

### Impacto

- **`ipWhites: "15.229.81.27"`** — IP whitelistado para A/B testing.
  Spoofing via `X-Forwarded-For: 15.229.81.27` pode bypassar regras de
  filtragem que dependem disso.
- **`device_user_limit: 2` / `ip_user_limit: 6`** — limites para
  multi-conta. Atacante sabe exatamente quantas contas pode criar
  por IP/device antes de ser detectado.
- **`bind_invite_code_bonus_reward: "50"`** — bônus de R$50 por bind
  de invite code. Combinado com o B8 (self-invite) é o vetor de farm.
- **`always_amount: "10000.00"`** — limite global de saque diário?
  Não fica claro, mas é um número que ajuda a fazer probing de limite.
- **`recharge_amount_max: 999999`** — confirma que o B1 pode tentar
  valores até `999998` antes do gateway recusar.

### Próximos passos

1. Tentar `X-Forwarded-For: 15.229.81.27` em endpoints de A/B (qualquer
   um) e ver se muda comportamento.
2. Documentar como evidência no relatório: a config inteira tá
   acessível pra qualquer user autenticado.

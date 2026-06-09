# 🔴 F09 — Token anão afeta pelo menos 8 endpoints (escopo muito maior que F01)

**Severidade:** CRÍTICA (ampliação do F01)
**Status:** Confirmado (varredura de 37 endpoints)
**Data:** 2026-06-09

## Resumo

A varredura completa de todos os endpoints do bundle JS revelou que
**8 endpoints** são vulneráveis ao token anão, não apenas o
`querySimpleBalance` do F01. O impacto do bug de autenticação é
consideravelmente maior do que o mapeado inicialmente.

## Endpoints vulneráveis confirmados

| Endpoint | Método | Aceita token anão | Tipo | Dados retornados |
|----------|--------|-------------------|------|-----------------|
| `/japi/user/balance/querySimpleBalance` | GET | ✅ | Leitura | saldo financeiro |
| `/japi/user/getExtraInfo` | GET | ✅ | Leitura | teleStatus, rechargeStatus (config) |
| `/japi/user/getDama` | GET | ✅ | Leitura | (data vazia — possivelmente volume de apostas) |
| `/japi/user/api/signIn/customerSignConfig` | GET | ✅ | Leitura | vipLevel, signNum, tabela de cashback |
| `/japi/user/api/signIn/v2/signIn` | POST | ✅ | **ESCRITA** | executa check-in em nome do uid |
| `/japi/user/vip/getAllDisplayVo` | GET | ✅ | Leitura | tabela de benefícios VIP de todos os níveis |
| `/japi/invite/boxConfig/boxReceiveRecord` | GET | ✅ | Leitura | histórico de caixas recebidas |
| `/prod-api/set/mains` | POST | Público | Leitura pública | config de manutenção |

## Análise por endpoint

### `/japi/user/getExtraInfo` — INFORMATIVO

Retorna `teleStatus` e `rechargeStatus`. Todos os uids testados
retornam os mesmos valores (`{"teleStatus":"1","rechargeStatus":"0"}`).
**Provavelmente é config global** do tenant, não dados do usuário.
Token anão aceito, mas sem impacto de privacidade comprovado.

### `/japi/user/getDama` — MÉDIO

Retorna data vazia (`{}`). "Dama" no contexto de plataformas de
jogos de azar asiáticas é um sistema de cálculo de volume de apostas
para distribuição de bônus para afiliados (similar a rake). Acesso
via token anão sem dados visíveis agora, mas o endpoint existe e aceita
o bypass — versão futura pode retornar dados sensíveis.

### `/japi/user/api/signIn/customerSignConfig` — ALTO

Retorna:
```json
{
  "vipLevel": 0,
  "todaySignFlag": true,
  "signNum": 1,
  "signConfigMapV2": {
    "V25": {"totalDays": 1830, "cashback": 2500.0},
    ...
  }
}
```

Expõe toda a tabela de cashback por nível VIP e o status de check-in
do usuário cujo uid foi usado no token anão.

### `/japi/user/api/signIn/v2/signIn` — CRÍTICO (ver F08)

Aceita token anão e executa check-in em nome do uid. Única escrita
confirmada via token anão.

### `/japi/user/vip/getAllDisplayVo` — BAIXO

Retorna a tabela de benefícios VIP de todos os níveis (é provavelmente
config global, não dados de usuário específico). Aceita token anão
mas sem impacto de privacidade.

### `/japi/invite/boxConfig/boxReceiveRecord` — MÉDIO

Retorna histórico de caixas recebidas do uid. Lista vazia para uid=1
(usuário novo). Com uids que têm histórico, pode expor transações.

## Impacto consolidado do token anão (F01 + F07 + F08 + F09)

| Aspecto | Antes (só F01) | Agora (F01+F07+F08+F09) |
|---------|---------------|------------------------|
| Endpoints afetados | 1 | 8 confirmados |
| Tipo de operação | Só leitura | Leitura + **1 escrita** |
| Escopo de tenants | amizade777 | amizade777 + rainha777slots (+ possivelmente mais) |
| Dados expostos | Saldo financeiro | Saldo + VIP + check-in + recompensas + histórico |
| Ação possível | Espionar saldo | Espionar + **interferir no check-in** |

## Recomendação

Mesma do F01/F08, com adição:

1. Fazer auditoria interna de **todos** os endpoints `/japi/*` que
   usam o parser de token — o escopo externo já encontrou 8, a
   superfície interna pode ser muito maior.
2. Priorizar patches nos endpoints de escrita (`/v2/signIn` e outros
   que agirão em nome do usuário).
3. Logging: adicionar alertas quando token sem `:` for recebido pra
   detectar exploração histórica.

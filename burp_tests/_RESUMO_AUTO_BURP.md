# Resumo da rodada automatizada — `auto_burp.py`

**Data:** 2026-06-09
**Script:** `auto_burp.py` + `verificar_t6.py`
**Estratégia:** login fresco antes de cada bloco (contorna TTL curto do
token).

---

## 🔴 1 ACHADO CRÍTICO

**Bypass de autenticação via "token anão"**
→ ver `extras/ACHADO_CRITICO_token_anao.md` para detalhes completos.

Resumo: enviar `Token: <uid>` (só o número) faz o backend retornar o
saldo de qualquer conta. uid=1 vazou saldo de R$ 24.475,00.

**Endpoints confirmadamente vulneráveis:**
- `GET /japi/user/balance/querySimpleBalance`
- `POST /prod-api/set/get` (config dump também aceita)

---

## 🟡 1 ACHADO MÉDIO

**Configuração financeira/operacional totalmente exposta**
- Endpoint: `POST /prod-api/set/get`
- Exposição: limites de saque/depósito, IP whitelist (`15.229.81.27`),
  bonus configs, multi-conta limits.
- Combinado com o bypass do token anão acima, **qualquer atacante sem
  credenciais consegue baixar a config inteira** da plataforma.

→ ver `extras/vazamentos_info.md` (V2)

---

## ⚪ Achados negativos (testes que NÃO encontraram vuln)

### B1 — Manipulação de valor no recharge (10 payloads)
Backend bloqueou todos com `code:103012` ou `code:400`. ✅ Validação OK.

### B3-equivalente — Race condition no claim
8 requisições paralelas em `/prod-api/invite/getBindRewardRecord` —
0 aceitas. ✅ Locking funciona.

### B4 — IDOR path-based
`/japi/user/player/<uid>` e variantes retornaram 404. Endpoint não
existe nesta versão. (Mas o bypass do token anão é IDOR de fato em
outro caminho.)

### B7 — Mass assignment
7 payloads diferentes em `POST /prod-api/player/update`. Todos
retornaram "Token expirou" (TTL ainda muito curto entre login e attack).
**Inconclusivo** — precisa retestar com login imediatamente antes de
cada attempt.

### B5 — Endpoints admin
26 paths testados. Maioria retornou 404/HTML do CloudFront. Nenhum
acesso admin obtido com user comum. ✅ Esperado.

### Header smuggling no recharge
14 headers candidatos (`X-Original-Amount`, `X-Forwarded-For`,
`X-Admin`, etc). Nenhum mudou o `code` de resposta. ✅ Headers
ignorados.

### Bypass de CDN (IPs internos)
`192.10.0.168:3001` e `172.16.0.245:3001` não respondem de fora. ✅
Firewall fechado.

### Token forging strict (T1-T5, T7, T8)
- T1 (uid=1, hash original): rejeitado ✅
- T2 (uid=137028, hash original): rejeitado ✅
- T3 (timestamp futuro): rejeitado ✅
- T4 (timestamp=0): rejeitado ✅
- T5 (sem hash): rejeitado ✅
- T7 (hash uppercase): rejeitado ✅
- T8 (4 candidatos de hash sem secret): todos rejeitados ✅

A validação **funciona** quando o token tem o formato 4-partes. O bug
é na rota de fallback (token sem `:`), não no parser principal.

---

## Próximos passos sugeridos

### Prioridade 1 — Mass assignment (refazer)
O bloco 3 falhou por TTL. Reescrever com login imediato e checar
`POST /prod-api/player/update` com os 7 payloads de novo.

### Prioridade 2 — Mapear todos os endpoints vulneráveis ao token anão
**Sem enumerar contas reais.** Apenas testar com uid=137027 (próprio)
qual lista de endpoints aceita `Token: 137027` retornando dados:

```python
endpoints = [
    "/japi/user/...",
    "/prod-api/...",
    # etc
]
for ep in endpoints:
    test(ep, token="137027")    # auth fraca
    test(ep, token="abc")       # negativa
    # endpoints onde 137027 retorna 200 e abc retorna 401 = vulneráveis
```

Isso amplia o impacto do achado crítico **sem** invadir contas alheias.

### Prioridade 3 — Reportar
O achado já é grave o suficiente para parar e reportar à faculdade
antes de continuar testando. **Recomendo:**
1. Compilar `extras/ACHADO_CRITICO_token_anao.md` num e-mail
2. Enviar pro responsável da faculdade
3. Aguardar autorização explícita para continuar/aprofundar

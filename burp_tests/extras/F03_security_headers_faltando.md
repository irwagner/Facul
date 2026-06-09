# 🟡 F03 — Headers de segurança ausentes + CORS permissivo

**Severidade:** MÉDIA
**Status:** Confirmado
**Hosts afetados:** `ds.amizade777.com` (provavelmente todos os tenants)

## F03.1 — 6 headers de segurança ausentes

`GET /` retorna apenas headers funcionais (Content-Type, ETag, Cache,
CloudFront), mas nenhum dos seguintes:

| Header faltando            | Função                                     |
|----------------------------|---------------------------------------------|
| Strict-Transport-Security  | Força HTTPS — protege contra downgrade     |
| Content-Security-Policy    | Mitiga XSS limitando origens                |
| X-Content-Type-Options     | `nosniff` — anti-MIME-confusion             |
| X-Frame-Options            | Anti-clickjacking                           |
| Referrer-Policy            | Controla vazamento de URL via Referer       |
| Permissions-Policy         | Restringe APIs do navegador                 |

### Impacto

- **Sem HSTS:** primeiro acesso pode ser interceptado por MITM (downgrade
  pra HTTP).
- **Sem CSP:** se o site tiver XSS reflexivo em qualquer ponto, atacante
  pode carregar scripts de qualquer origem.
- **Sem X-Frame-Options:** página pode ser embedada em iframe num site
  malicioso → clickjacking pra disparar ações do usuário sem ele saber.
- **Sem nosniff:** uploads de arquivo podem ser servidos com tipo
  errado e executados como script.

### Correção

No CloudFront ou no nginx do origin:

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; img-src 'self' data: https:; connect-src 'self' wss://*.amizade777.com" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

## F03.2 — CORS com `Access-Control-Allow-Origin: *`

Pre-flight de `Origin: https://attacker.com`:

```
HTTP/2 200 OK
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: (vazio)
```

### Análise

- `ACO: *` é permissivo demais, mas isoladamente **não é catastrófico**
  porque `Access-Control-Allow-Credentials` está vazio (default = false).
  Sem credentials, browser não envia cookies/Token na request CORS.
- **MAS** a aplicação usa header `Token: ...` (não cookie). Se um site
  malicioso tem o token (via XSS, phishing, ou roubo via outro vetor),
  ele pode chamar a API direto do navegador da vítima.

### Recomendação

Restringir `Access-Control-Allow-Origin` à lista de domínios próprios:

```
Access-Control-Allow-Origin: https://ds.amizade777.com
Vary: Origin
```

E nunca enviar `Access-Control-Allow-Credentials: true` se o ACO for `*`.

## Reprodução

```bash
curl -I -k 'https://ds.amizade777.com/' | grep -iE '(strict|content-security|frame|sniff|referrer|permissions)'

curl -k -X OPTIONS 'https://ds.amizade777.com/japi/user/balance/querySimpleBalance' \
  -H 'Origin: https://attacker.com' \
  -H 'Access-Control-Request-Method: GET' \
  -i
```

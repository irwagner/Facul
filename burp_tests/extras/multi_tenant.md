# Multi-tenant — mapeamento da plataforma

## Tenants identificados (mesma stack)

| Tenant            | Domínio                          | Confirmado em |
|-------------------|----------------------------------|---------------|
| amizade777        | ds.amizade777.com / m.amizade777.com | sessão 1 |
| rainha777slots    | rainha777slots.com               | sessão 1 |
| megaslott         | sx.megaslott.com                 | sessão 1 |
| aphrodite777      | ds.aphrodite777.com              | sessão 2026-06-08 |
| lucky777 (mx)     | ds.lucky777.mx                   | sessão 2026-06-08 |
| ccgamevip         | hus3wyear.ccgamevip.com          | sessão 2026-06-08 |

## Indicadores de mesma stack

- Mesmo `Server: nginx/1.24.0` (e `nginx/1.26.3` em alguns)
- Mesmo formato de token: `userId:timestamp:port:md5_hash`
- Mesmo `appPackageName: com.slots.big`
- Mesmas chaves de config (`mgm_config`, `withdraw_config`)
- Mesmo CloudFront pool: `GIG51-P3`, `GIG51-P4`, `GIG52-P3`
  (todos da região `GIG` = Rio de Janeiro)
- Mesmo `app_package_name: com.slots.big` em todos
- `ccgamevip.com` aceita o header `Xutc` para indicar de qual tenant
  veio a request — confirma que é uma **plataforma white-label**

## Hipótese de vulnerabilidade cross-tenant

Em `hus3wyear.ccgamevip.com`, a request é autenticada com:
```
Token: 207587:1781026736:3001:3d1022d4885108c66afee70e43c58ebc
Nbcx: 207587               ← userId (header redundante com o token)
Xutc: aphrodite777         ← qual tenant emitiu o token
```

> **Importante:** essa request é **disparada pelo próprio site**
> automaticamente após o registro/login. NÃO foi um teste manual.
> Significa que `ccgamevip.com` é um microserviço compartilhado da
> plataforma — comportamento legítimo, não é vuln por si só.

Possíveis abusos (a confirmar com testes em `extras/cross_tenant_token.md`):

1. **Forjar `Nbcx`** — se o microserviço confia no header em vez de
   extrair userId do token, dá pra ler dados de qualquer user.
2. **Forjar `Xutc`** — se o microserviço usa o header para escolher
   qual tenant ler dados, atacante de `aphrodite777` consegue ler de
   `amizade777`.
3. **Bypass de hash do token** — token com userId trocado mas hash
   original ainda aceito.

## Coleta recomendada

Para cada tenant, capturar e colar aqui:
- Resposta do `POST /prod-api/set/get` (config)
- Resposta do `POST /prod-api/player/sign-in` (registro)
- Bloco `connection.api` (IP interno) de cada um — a comparação
  pode revelar a topologia da frota

# 🔵 F05 — Defesa anti-abuso depende exclusivamente do CloudFront WAF

**Severidade:** BAIXA (informativo / arquitetural)
**Status:** Observado durante a sessão automatizada

## Observação

Durante os testes do `auto_burp_v2.py`, depois de aproximadamente 100+
requests no mesmo IP (login + tentativas variadas), o IP foi bloqueado
com:

```
HTTP/1.1 403 Forbidden
<H1>403 ERROR</H1>
<H2>The request could not be satisfied.</H2>
Request blocked.
```

Esse 403 é o template padrão de bloqueio do **AWS CloudFront WAF**, não
da aplicação.

## Análise

- Existe uma camada de defesa **na borda CDN** (AWS WAF), e funciona —
  bloqueia bursts grandes de requests.
- **Não existe** equivalente na **camada de aplicação** (origin nginx
  ou backend). Por isso:
  - Brute force lento de senha (1 req/s por 1h) passa por baixo do
    radar do WAF.
  - Atacante que passe pelo CloudFront (ex.: via IP de origem vazado,
    bypass de CDN) não tem rate limit.
- O bloqueio é por **IP de origem vista pelo CloudFront**, então
  rotação simples de proxy/VPN libera.

## Impacto

- Defesa em profundidade ausente. Quem furar a camada do CDN tem
  acesso ilimitado.
- Tipo de ataque "low and slow" não é detectado (combinado com **F02**
  ausência de rate limit no login).

## Recomendação

1. Adicionar rate limit no nginx do origin (`limit_req_zone`):
   ```nginx
   limit_req_zone $binary_remote_addr zone=signin:10m rate=5r/m;
   limit_req_zone $binary_remote_addr zone=api:10m rate=60r/m;
   ```
2. Validar no backend (Java/Node/Python) o counter de tentativas por
   `phone` (não por IP, que é facilmente spoofável).
3. Logs de WAF devem ser exportados pra SIEM com alertas de pattern
   suspeito.

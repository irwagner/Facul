# 🟠 F02 — Ausência de rate limiting no login

**Severidade:** ALTA
**Endpoint:** `POST /prod-api/player/sign-in`
**Status:** Confirmado (10 tentativas erradas seguidas, sem bloqueio)

## Evidência

10 tentativas de login com senha errada, todas em sequência rápida:

```
Tentativa 1: HTTP=200 code=102002 latencia=252ms
Tentativa 2: HTTP=200 code=102002 latencia=277ms
...
Tentativa 10: HTTP=200 code=102002 latencia=241ms
```

`code=102002` = "senha incorreta". Todas as 10 retornaram a mesma
mensagem com latência consistente (~250ms). Nenhuma foi bloqueada.

> **Observação posterior:** após **outras** centenas de requests
> (testes de mass assignment etc.), o IP foi bloqueado pelo AWS
> CloudFront WAF (HTTP 403). Mas o bloqueio veio do **CDN**, não da
> aplicação, e ocorreu por volume total de tráfego, não por
> tentativas de login específicas.

## Impacto

- **Brute force**: atacante pode tentar ~3-4 tentativas/segundo por IP.
  Com botnet ou rotação de IP, viável testar dicionário inteiro.
- **Credential stuffing**: lista de credenciais vazadas em outros
  serviços pode ser testada em massa.
- **Conta-alvo já fraca**: a credencial padrão observada na sessão
  é `phone == password` (`21998498419` / `21998498419`). Se for padrão
  do registro, **todas as contas novas têm senha igual ao telefone
  durante alguma janela de tempo** — cenário catastrófico.

## Causa raiz hipotética

- Não existe contador de falhas por (telefone, IP) na camada de
  aplicação.
- O AWS WAF está configurado pra rate limit GLOBAL do site (proteção
  DDoS), não pra detectar pattern de brute force em endpoint específico.

## Recomendação de correção

1. **Curto prazo (app):**
   - Implementar contador de falhas por `(phone, IP)` em Redis com TTL.
   - Após 5 falhas em 5 min: retornar `code:102099` + delay artificial
     de 2s e exigir CAPTCHA na próxima tentativa.
   - Após 10 falhas em 1h: bloquear o IP por 1h pra esse endpoint.
2. **Médio prazo (WAF):**
   - Criar rule específica no AWS WAF: > 30 POST em
     `/prod-api/player/sign-in` em 5min do mesmo IP → bloqueio 1h.
3. **Política:**
   - Revisar a política de senha padrão (phone==password).
     Se for fato durante registro, alterar pra exigir senha forte
     desde o início.
   - Implementar 2FA por SMS/email.

## Reprodução

```bash
for i in {1..15}; do
  curl -s -k 'https://ds.amizade777.com/prod-api/player/sign-in' \
    -H 'Content-Type: application/json' \
    -d '{"phone":"21998498419","password":"errado","appPackageName":"com.slots.big","deviceId":"x","deviceModel":"WEB","deviceVersion":"WEB","appVersion":"1.0.0","appChannel":"pc"}'
done | grep -c '102002'
```

Esperado após correção: `< 5` (ou erro de bloqueio nos demais).
Atual: `15`.

# B6 — Bypass de CDN (acesso direto à origem)

**Objetivo:** Identificar o IP real do backend (atrás do CloudFront) e
verificar se ele aceita conexões diretas — o que dispensa o WAF e
permite atacar sem proteção.

---

## IPs candidatos

> Cole aqui os IPs da seção `origin_candidates.promising` do output do
> `pentest_avancado.py`.

```
<lista de IPs>
```

## Tabela de testes

| IP candidato | Porta | Host header              | Status | Tamanho body | Igual à origem? |
|--------------|-------|---------------------------|--------|--------------|------------------|
|              | 443   | ds.amizade777.com         |        |              |                  |
|              | 80    | ds.amizade777.com         |        |              |                  |
|              | 443   | m.amizade777.com          |        |              |                  |
|              | 8080  | ds.amizade777.com         |        |              |                  |
|              | 8443  | ds.amizade777.com         |        |              |                  |

## Como configurar no Burp

1. Repeater → painel da request → ícone do alvo (Target) no canto
   superior direito
2. Trocar `Host` para o IP candidato e a porta (ex.: `203.0.113.10:443`)
3. Marcar `Use HTTPS`
4. **Não** desmarcar `Update Host header`. O Host real do site
   (`ds.amizade777.com`) já está dentro da request.
5. Send

## Confirmações

> Para cada IP que respondeu com algo parecido com o site real, cole a
> primeira linha de resposta + tamanho do body.

```
<exemplo>
IP 203.0.113.10:443
HTTP/1.1 200 OK
Content-Length: 12345
Server: nginx
```

## Próximo passo se algum IP confirmar

- Anotar o IP confirmado e usar ele como base para os próximos testes
  (B1-B5) bypassando o WAF.
- Se múltiplos IPs respondem, anotar todos.

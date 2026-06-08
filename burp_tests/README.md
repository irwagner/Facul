# Resultados dos Testes Manuais com Burp Suite

Esta pasta concentra TUDO que você capturar durante a sessão prática com
Burp Suite no `amizade777.com`. Cole aqui as requests, responses e
observações de cada teste do `PASSO_A_PASSO_MANUAL.md`.

---

## Como usar

1. Para cada teste do bloco B (B1 até B10), abra o arquivo correspondente
   nesta pasta e preencha as seções.
2. Não precisa formatar bonito. **Cole bruto**: copia do Burp Repeater
   (Ctrl+A → copy) e joga aqui dentro de blocos ` ``` `.
3. Se um teste não fizer sentido (ex.: endpoint retornou 404 antes de
   testar payloads), anote isso mesmo — é resultado.
4. Quando terminar uma sessão, me avise. Eu leio tudo que estiver aqui e
   gero a análise.

---

## Estrutura

```
burp_tests/
├── README.md                     ← este arquivo
├── 00_setup.md                   ← evidência de que o proxy ficou ok
├── B1_deposito_anomalo.md        ← POST /prod-api/pay-service/recharge
├── B2_saque_anomalo.md           ← POST /prod-api/payment/balance-less
├── B3_race_condition_saque.md    ← Intruder / Turbo Intruder
├── B4_idor.md                    ← perfil/saldo/transações de outros IDs
├── B5_admin_panel.md             ← descoberta de endpoints admin
├── B6_bypass_cdn.md              ← origem real (IP candidato)
├── B7_escalada_privilegio.md     ← POST /prod-api/player/update
├── B8_self_invite.md             ← abuso de bônus de convite
├── B9_injecoes_cadastro.md       ← SQLi/NoSQLi/XSS/LDAP em registro
├── B10_token_manipulado.md      ← análise do token custom
├── extras/                       ← qualquer coisa que não se encaixe
└── raw/                          ← dumps brutos (HAR, JSON, prints)
```

---

## Convenção de preenchimento

Cada arquivo `B*.md` tem o mesmo template:

```markdown
## Payload N — <descrição curta>

### Request
```
<cola tudo do Repeater aqui: linha do método, headers, corpo>
```

### Response
```
<cola tudo da resposta aqui: status, headers, body>
```

### Observação
- Saldo mudou? Sim/Não/Não consegui verificar
- Erro retornado: <código + mensagem>
- Comportamento estranho: <ex.: retornou 200 mas saldo não mudou>
```

---

## Atalhos do Burp que você vai usar muito

| Atalho       | Função                                         |
|--------------|------------------------------------------------|
| Ctrl+R       | Send to Repeater                               |
| Ctrl+I       | Send to Intruder                               |
| Ctrl+A       | Selecionar tudo (no Repeater request/response) |
| Ctrl+C       | Copiar                                         |
| Ctrl+Espaço  | Enviar request no Repeater                     |

Para copiar uma request inteira como texto, no Repeater clique direito
no painel da request → **Copy to file** ou **Copy as curl command**.

---

## Quando precisar de ajuda no meio do teste

- Se o site fizer logout antes de você terminar, **não tenta logar de
  novo na mesma janela**. Feche tudo, reabra o Brave com proxy ligado, e
  comece de novo. Captura um token novo via login.
- Se aparecer 401/403 do nada, o token expirou (TTL ~5-10 min). Faz
  login de novo pelo navegador, captura o novo token, e continua.
- Se o WAF bloquear, espera ~5 min sem fazer request. O bloqueio é por
  IP+rate, não permanente.

---

## Atributos importantes da sessão

- **Site desktop:** https://ds.amizade777.com (CloudFront, 18.64.207.51)
- **Site mobile:** https://m.amizade777.com (CloudFront, 18.161.205.69)
- **Login:** phone=21998498419 password=21998498419
- **UserID:** 137027
- **Nickname:** G137027
- **DeviceId:** 0beb614f-8838-43ef-00fc-0029f7d5d20f
- **InviteCode:** zudp7lqx

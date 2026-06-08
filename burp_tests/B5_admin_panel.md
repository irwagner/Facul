# B5 — Descoberta de painel admin

**Objetivo:** Achar endpoints administrativos / de debug que não exigem
permissão ou aceitam o token de jogador comum.

> Use o Repeater. Para cada path, faça GET com o token válido e anote o
> status. 200/302 = interessante, 401/403 = existe mas protegido,
> 404 = não existe, 405 = existe mas método errado.

---

## Tabela

| Path                                      | Status | Body curto / observação           |
|-------------------------------------------|--------|------------------------------------|
| /prod-api/admin/player/list               |        |                                    |
| /prod-api/admin/user/list                 |        |                                    |
| /prod-api/admin/finance                   |        |                                    |
| /prod-api/admin/config                    |        |                                    |
| /prod-api/admin/recharge/list             |        |                                    |
| /prod-api/admin/withdraw/list             |        |                                    |
| /japi/admin/user/list                     |        |                                    |
| /manage/player                            |        |                                    |
| /manage/finance                           |        |                                    |
| /system/admin                             |        |                                    |
| /system/config                            |        |                                    |
| /system/log                               |        |                                    |
| /superadmin                               |        |                                    |
| /backoffice                               |        |                                    |
| /operator                                 |        |                                    |
| /staff                                    |        |                                    |
| /internal                                 |        |                                    |
| /debug                                    |        |                                    |
| /actuator                                 |        |                                    |
| /actuator/health                          |        |                                    |
| /actuator/env                             |        |                                    |
| /actuator/heapdump                        |        |                                    |
| /swagger-ui.html                          |        |                                    |
| /swagger                                  |        |                                    |
| /v2/api-docs                              |        |                                    |
| /v3/api-docs                              |        |                                    |
| /api-docs                                 |        |                                    |

## Achados notáveis

> Cole aqui as responses dos paths que retornaram algo interessante
> (200/302, mensagem de erro reveladora, ou stacktrace).

```
```

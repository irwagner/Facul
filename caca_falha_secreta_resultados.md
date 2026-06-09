# Resultados — caca_falha_secreta.py

_2026-06-09T18:00:27.966808_

- 🔴 critical: 5
- 🟠 high: 7
- 🟡 medium: 6
- 🔵 low: 0
- ⚪ info: 14

---

### [CRITICAL] new_endpoint — GET /japi/user/getExtraInfo

**Interpretação:** Token anão aceito! data_keys=['teleStatus', 'rechargeStatus']

```json
Req: {"method": "GET", "path": "/japi/user/getExtraInfo", "tokens": {"anao": 1, "sem": "none", "valido": "..."}}
Resp: {"code_anao": 200, "code_sem_token": 401, "code_valido": 200, "data_keys_anao": ["teleStatus", "rechargeStatus"], "data_keys_valido": ["teleStatus", "rechargeStatus"], "sample_anao": "{\"teleStatus\": \"1\", \"rechargeStatus\": \"0\"}"}
```

---

### [CRITICAL] new_endpoint — POST /japi/user/api/signIn/v2/signIn

**Interpretação:** Token anão aceito! data_keys=['reward']

```json
Req: {"method": "POST", "path": "/japi/user/api/signIn/v2/signIn", "tokens": {"anao": 1, "sem": "none", "valido": "..."}}
Resp: {"code_anao": 200, "code_sem_token": 401, "code_valido": 200, "data_keys_anao": ["reward"], "data_keys_valido": ["reward"], "sample_anao": "{\"reward\": 0}"}
```

---

### [CRITICAL] new_endpoint — GET /japi/user/api/signIn/customerSignConfig

**Interpretação:** Token anão aceito! data_keys=['vipLevel', 'todaySignFlag', 'signNum', 'signConfigMapV2'] | Dados sensíveis com token válido: ['vipLevel']

```json
Req: {"method": "GET", "path": "/japi/user/api/signIn/customerSignConfig", "tokens": {"anao": 1, "sem": "none", "valido": "..."}}
Resp: {"code_anao": 200, "code_sem_token": 401, "code_valido": 200, "data_keys_anao": ["vipLevel", "todaySignFlag", "signNum", "signConfigMapV2"], "data_keys_valido": ["vipLevel", "todaySignFlag", "signNum", "signConfigMapV2"], "sample_anao": "{\"vipLevel\": 0, \"todaySignFlag\": true, \"signNum\": 1, \"signConfigMapV2\": {\"V21\": {\"totalDays\": 480, \"cashback\": 500.0}, \"V20\": {\"totalDays\": 300, \"cashback\": 400.0}, \"V23\": {\"totalDays\": 653, \"cashback\": 1500.0}, \"V22\": {\"totalDays\": 480, \"cashback\": 1000.0}, \"V25\": {\"totalDays\": 1830, \"cashback\": 25"}
```

---

### [CRITICAL] getExtraInfo — GET token_anao_1

**Interpretação:** Retornou dados! Verificar conteúdo.

```json
Req: {"method": "GET", "token_type": "token_anao_1"}
Resp: {"code": 200, "data_keys": ["teleStatus", "rechargeStatus"], "data": "{\"teleStatus\": \"1\", \"rechargeStatus\": \"0\"}"}
```

---

### [CRITICAL] getExtraInfo — GET token_anao_137027

**Interpretação:** Retornou dados! Verificar conteúdo.

```json
Req: {"method": "GET", "token_type": "token_anao_137027"}
Resp: {"code": 200, "data_keys": ["teleStatus", "rechargeStatus"], "data": "{\"teleStatus\": \"1\", \"rechargeStatus\": \"0\"}"}
```

---

### [HIGH] new_endpoint — GET /japi/user/getDama

**Interpretação:** Token anão aceito! data_keys=[]

```json
Req: {"method": "GET", "path": "/japi/user/getDama", "tokens": {"anao": 1, "sem": "none", "valido": "..."}}
Resp: {"code_anao": 200, "code_sem_token": 401, "code_valido": 200, "data_keys_anao": null, "data_keys_valido": [], "sample_anao": null}
```

---

### [HIGH] new_endpoint — POST /prod-api/set/mains

**Interpretação:** Token anão aceito! data_keys=None | Endpoint público (sem auth)!

```json
Req: {"method": "POST", "path": "/prod-api/set/mains", "tokens": {"anao": 1, "sem": "none", "valido": "..."}}
Resp: {"code_anao": 200, "code_sem_token": 200, "code_valido": 200, "data_keys_anao": null, "data_keys_valido": null, "sample_anao": "\"{\\r\\n    \\\"flag\\\": 0,\\r\\n    \\\"start\\\": \\\"2024-08-22 11:30:00\\\",\\r\\n    \\\"end\\\": \\\"2024-08-22 11:50:00\\\"\\r\\n}\""}
```

---

### [HIGH] new_endpoint — GET /japi/user/vip/getAllDisplayVo

**Interpretação:** Token anão aceito! data_keys=None

```json
Req: {"method": "GET", "path": "/japi/user/vip/getAllDisplayVo", "tokens": {"anao": 1, "sem": "none", "valido": "..."}}
Resp: {"code_anao": 200, "code_sem_token": 401, "code_valido": 200, "data_keys_anao": null, "data_keys_valido": null, "sample_anao": "[{\"level\": 0, \"rechargeAmountLimit\": 0, \"flowLimit\": 0, \"withdrawAmountLimitDay\": 10000, \"withdrawTimesLimitDay\": 1, \"receiveAmountLimitDay\": 0, \"display\": 1, \"upRewardAmout\": 0}, {\"level\": 1, \"rechargeAmountLimit\": 2000, \"flowLimit\": 20000, \"withdrawAmountLimitDay\": 20000, \"withdrawTimesLimitDay\": "}
```

---

### [HIGH] new_endpoint — POST /prod-api/mail/getMailCount

**Interpretação:** Token anão aceito! data_keys=None | Endpoint público (sem auth)!

```json
Req: {"method": "POST", "path": "/prod-api/mail/getMailCount", "tokens": {"anao": 1, "sem": "none", "valido": "..."}}
Resp: {"code_anao": 200, "code_sem_token": 200, "code_valido": 200, "data_keys_anao": null, "data_keys_valido": null, "sample_anao": null}
```

---

### [HIGH] new_endpoint — GET /japi/invite/boxConfig/boxReceiveRecord

**Interpretação:** Token anão aceito! data_keys=None

```json
Req: {"method": "GET", "path": "/japi/invite/boxConfig/boxReceiveRecord", "tokens": {"anao": 1, "sem": "none", "valido": "..."}}
Resp: {"code_anao": 200, "code_sem_token": 401, "code_valido": 200, "data_keys_anao": null, "data_keys_valido": null, "sample_anao": null}
```

---

### [HIGH] new_endpoint — POST /prod-api/notice/list

**Interpretação:** Token anão aceito! data_keys=None | Endpoint público (sem auth)!

```json
Req: {"method": "POST", "path": "/prod-api/notice/list", "tokens": {"anao": 1, "sem": "none", "valido": "..."}}
Resp: {"code_anao": 200, "code_sem_token": 200, "code_valido": 200, "data_keys_anao": null, "data_keys_valido": null, "sample_anao": null}
```

---

### [HIGH] getExtraInfo — GET token_valido

**Interpretação:** Retornou dados! Verificar conteúdo.

```json
Req: {"method": "GET", "token_type": "token_valido"}
Resp: {"code": 200, "data_keys": ["teleStatus", "rechargeStatus"], "data": "{\"teleStatus\": \"1\", \"rechargeStatus\": \"0\"}"}
```

---

### [MEDIUM] websocket — /ws

**Interpretação:** WebSocket endpoint respondeu!

```json
Req: {"path": "/ws", "upgrade": true}
Resp: {"http": 200, "is_websocket": false, "headers": {"Connection": "close"}}
```

---

### [MEDIUM] websocket — /websocket

**Interpretação:** WebSocket endpoint respondeu!

```json
Req: {"path": "/websocket", "upgrade": true}
Resp: {"http": 200, "is_websocket": false, "headers": {"Connection": "close"}}
```

---

### [MEDIUM] websocket — /socket

**Interpretação:** WebSocket endpoint respondeu!

```json
Req: {"path": "/socket", "upgrade": true}
Resp: {"http": 200, "is_websocket": false, "headers": {"Connection": "close"}}
```

---

### [MEDIUM] websocket — /socket.io/

**Interpretação:** WebSocket endpoint respondeu!

```json
Req: {"path": "/socket.io/", "upgrade": true}
Resp: {"http": 200, "is_websocket": false, "headers": {"Connection": "close"}}
```

---

### [MEDIUM] websocket — /sockjs/

**Interpretação:** WebSocket endpoint respondeu!

```json
Req: {"path": "/sockjs/", "upgrade": true}
Resp: {"http": 200, "is_websocket": false, "headers": {"Connection": "close"}}
```

---

### [MEDIUM] websocket — /japi/ws

**Interpretação:** WebSocket endpoint respondeu!

```json
Req: {"path": "/japi/ws", "upgrade": true}
Resp: {"http": 200, "is_websocket": false, "headers": {"Connection": "close"}}
```

---


teste deposito repeater, vou ir colando o request e response em sequencia. 

POST /prod-api/pay-service/recharge HTTP/2
Host: ds.amizade777.com
Content-Length: 176
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: pt-BR,pt;q=0.9
Sec-Ch-Ua: "Not-A.Brand";v="24", "Chromium";v="146"
Content-Type: application/json
Token: 137027:1780956891:3001:7964d1412a3f879b5472841e51bf735f
Sec-Ch-Ua-Mobile: ?0
Accept: */*
Origin: https://ds.amizade777.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://ds.amizade777.com/rechargeNext
Accept-Encoding: gzip, deflate, br
Priority: u=1, i

{"token":"137027:1780956891:3001:7964d1412a3f879b5472841e51bf735f","appPackageName":"com.slots.big","appVersion":"1.0.0","phone":"21998498419","configId":"","amount":-20,"qr":1}

HTTP/2 200 OK
Content-Type: application/json
Server: nginx/1.24.0
Date: Mon, 08 Jun 2026 22:22:58 GMT
Expires: -1
Access-Control-Allow-Origin: *
Cache-Control: private, must-revalidate
Pragma: no-cache
X-Cache: Miss from cloudfront
Via: 1.1 bd884746fc4f95bb4d1c6244fde881be.cloudfront.net (CloudFront)
X-Amz-Cf-Pop: GIG51-P3
X-Amz-Cf-Id: njWRVf-mHq8qzE6HXyzD8240CWLnwsccnrv7laSfstDOQscb3oCkig==

{"code":103012,"msg":"Valor de recarga errado, por favor verifique"}

----------------------------------------------

POST /prod-api/pay-service/recharge HTTP/2
Host: ds.amizade777.com
Content-Length: 176
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: pt-BR,pt;q=0.9
Sec-Ch-Ua: "Not-A.Brand";v="24", "Chromium";v="146"
Content-Type: application/json
Token: 137027:1780956891:3001:7964d1412a3f879b5472841e51bf735f
Sec-Ch-Ua-Mobile: ?0
Accept: */*
Origin: https://ds.amizade777.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://ds.amizade777.com/rechargeNext
Accept-Encoding: gzip, deflate, br
Priority: u=1, i

{"token":"137027:1780956891:3001:7964d1412a3f879b5472841e51bf735f","appPackageName":"com.slots.big","appVersion":"1.0.0","phone":"21998498419","configId":"","amount":-2,"qr":1}

HTTP/2 200 OK
Content-Type: application/json
Server: nginx/1.24.0
Date: Mon, 08 Jun 2026 22:23:28 GMT
Expires: -1
Access-Control-Allow-Origin: *
Cache-Control: private, must-revalidate
Pragma: no-cache
X-Cache: Miss from cloudfront
Via: 1.1 bd884746fc4f95bb4d1c6244fde881be.cloudfront.net (CloudFront)
X-Amz-Cf-Pop: GIG51-P3
X-Amz-Cf-Id: vo3L5PraBPIK5kj50BZbO2ZjPpWrgF1cVGhvDvmgKFJBisX-eduzaw==

{"code":103012,"msg":"Valor de recarga errado, por favor verifique"}

-----------------------------------------

POST /prod-api/pay-service/recharge HTTP/2
Host: ds.amizade777.com
Content-Length: 190
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: pt-BR,pt;q=0.9
Sec-Ch-Ua: "Not-A.Brand";v="24", "Chromium";v="146"
Content-Type: application/json
Token: 137027:1780956891:3001:7964d1412a3f879b5472841e51bf735f
Sec-Ch-Ua-Mobile: ?0
Accept: */*
Origin: https://ds.amizade777.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://ds.amizade777.com/rechargeNext
Accept-Encoding: gzip, deflate, br
Priority: u=1, i

{"token":"137027:1780956891:3001:7964d1412a3f879b5472841e51bf735f","appPackageName":"com.slots.big","appVersion":"1.0.0","phone":"21998498419","configId":"","amount":9007199254740991,"qr":1}

HTTP/2 200 OK
Content-Type: application/json
Server: nginx/1.24.0
Date: Mon, 08 Jun 2026 22:25:31 GMT
Expires: -1
Access-Control-Allow-Origin: *
Cache-Control: private, must-revalidate
Pragma: no-cache
X-Cache: Miss from cloudfront
Via: 1.1 cee631d073f7ec53b796b7878629db3c.cloudfront.net (CloudFront)
X-Amz-Cf-Pop: GIG51-P3
X-Amz-Cf-Id: i2XpcJx1KcRxx3IbV5EqJIUDZfqhCSTtp_TyHl5Y4hynRKIO12c_sw==

{"code":103014,"msg":"No available channel."}

---------------------------------------------------

em relação a isso aqui, se eu colocar qual quer numero me volta esse resultado, acho q é algo exploravel. 

/japi/user/balance/querySimpleBalance?userId=137028 

GET /japi/user/balance/querySimpleBalance?userId=137028 HTTP/2
Host: ds.amizade777.com
Sec-Ch-Ua-Platform: "Windows"
Cache-Control: no-cache
Accept-Language: pt-BR,pt;q=0.9
Sec-Ch-Ua: "Not-A.Brand";v="24", "Chromium";v="146"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Content-Type: application/json
Token: 137027:1780956891:3001:7964d1412a3f879b5472841e51bf735f
Accept: */*
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://ds.amizade777.com/wallet?status=recharge
Accept-Encoding: gzip, deflate, br
Priority: u=1, i



HTTP/2 200 OK
Content-Type: application/json
Server: nginx/1.24.0
Date: Mon, 08 Jun 2026 22:41:57 GMT
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Cache: Miss from cloudfront
Via: 1.1 96c98ad1bc6a5869d154d108ca8cb144.cloudfront.net (CloudFront)
X-Amz-Cf-Pop: GIG51-P3
X-Amz-Cf-Id: BnbmJdh--Tz9_vRLDaj1Ag1v_WnHV6Y-mHgpF8KtmiZI8kLPceSiJg==

{"code":200,"msg":null,"data":{"amount":0,"withdrawAmount":0,"inviteAmount":0},"total":0}


---------------------------------------------------

registro 

POST /prod-api/player/sign-in HTTP/1.1
Host: ds.aphrodite777.com
Content-Length: 763
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: pt-BR,pt;q=0.9
Sec-Ch-Ua: "Not-A.Brand";v="24", "Chromium";v="146"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
Content-Type: application/json
Token: 
Origin: https://ds.aphrodite777.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://ds.aphrodite777.com/
Accept-Encoding: gzip, deflate, br
Priority: u=1, i
Connection: keep-alive

{"appChannel":"pc","appPackageName":"com.slots.big","deviceId":"db2eae3f-6b20-4418-a279-0fac1ff522c8","deviceModel":"WEB","deviceVersion":"WEB","appVersion":"1.0.0","sysTimezone":null,"sysLanguage":null,"phone":"2199985989","password":"2199985989","rephone":"2199985989","verifyCode":"register","web_finger":{"cpuSize":4,"canvas":"7c6b224645b06ad8aaa1717f7365d7e4","webgl":"c9e870d24232dc101def18eeeb0569d5","userAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36","screenWidth":1351,"inviteUrl":"https://ds.aphrodite777.com"},"installTime":"1781026672081","captcha_image_key":"ccd69d26-86eb-41e1-b03b-68e9396fb8cf","captcha_image_code":"5p8c","web_uuid":"db2eae3f-6b20-4418-a279-0fac1ff522c8"}


HTTP/2 200 OK
Content-Type: application/json
Server: nginx/1.24.0
Date: Tue, 09 Jun 2026 17:38:56 GMT
Expires: -1
Access-Control-Allow-Origin: *
Cache-Control: private, must-revalidate
Pragma: no-cache
X-Cache: Miss from cloudfront
Via: 1.1 e09adab5f2c0b994b1a507ad05d8970c.cloudfront.net (CloudFront)
X-Amz-Cf-Pop: GIG51-P4
X-Amz-Cf-Id: V94V0hwMT05gN7SvH2VDoFfIogGaMAN69Tb4wLv_cyePy7trXDFGpw==

{"code":200,"msg":"success","data":{"user_info":{"client_ip":"201.17.26.194","user_id":207587,"nickname":"G207587","avatar":"1","fb_avatar":"","phone":"2199985989","pay_account_id":"","vip_level":0,"vip_level_max":0,"card_back":0,"avatar_frame":0,"app_package_name":"com.slots.big","bind":[1],"invite_user_id":"","invite_code":null,"invite":{},"is_register":1,"enable":1,"recharge_amount":0,"withdraw_amount":0,"s_player":0,"c_player":0,"withdraw_model":1,"total_rounds":0,"bind_bank_reward":0,"first_rw_reward":0,"withdraw_control":-1,"created_at":1781026735,"ab":"A","ab_open":0},"bank":{},"pay_account":{"email":"hcg@rummy.com","phone":"2199985989","name":"G207587"},"connection":{"ip":"wss:\/\/ds.aphrodite777.com\/websocket6","port":3001,"server_id":600,"api":"http:\/\/192.10.0.168:3001\/api"},"token":"207587:1781026736:3001:3d1022d4885108c66afee70e43c58ebc","recharge_dot":[],"hide_entrance":[],"game_list":[55,52,51,50,53,56,30,10001,10002,10003,10004,10005,20001,20002,20003,20004,20005,11,12,25]}}


------------------------------

apos o cadastro apareceu isso tb

POST /prod-api/set/get HTTP/1.1
Host: ds.aphrodite777.com
Content-Length: 73
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: pt-BR,pt;q=0.9
Sec-Ch-Ua: "Not-A.Brand";v="24", "Chromium";v="146"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
Content-Type: application/json
Token: 207587:1781026736:3001:3d1022d4885108c66afee70e43c58ebc
Origin: https://ds.aphrodite777.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://ds.aphrodite777.com/
Accept-Encoding: gzip, deflate, br
Priority: u=1, i
Connection: keep-alive

{"appChannel":"pc","appVersion":"1.0.0","appPackageName":"com.slots.big"}


HTTP/2 200 OK
Content-Type: application/json
Server: nginx/1.24.0
Date: Tue, 09 Jun 2026 17:38:56 GMT
Expires: -1
Access-Control-Allow-Origin: *
Cache-Control: private, must-revalidate
Pragma: no-cache
X-Cache: Miss from cloudfront
Via: 1.1 e09adab5f2c0b994b1a507ad05d8970c.cloudfront.net (CloudFront)
X-Amz-Cf-Pop: GIG51-P4
X-Amz-Cf-Id: iEOU8JUR1fYrE0NgvjLRJow-lKJP2fg4W4ndrV6oP0muV4T1M6NZyA==

{"code":200,"msg":"success","data":{"recharge_options":[20,30,40,50,80,100,200,300,500,800,1000,2000,3000,5000,8000,10000,20000,30000,50000,80000],"recharge_amount_min":20,"current":"1.0.1","forceUpdate":"1.0.0","url_download":"http:\/\/m.aphrodite777.com\/","withdraw_fee":0.06,"withdraw_min":50,"withdraw_step":100,"maintenance":{"flag":0,"start":"2024-06-28 01:30:00","end":"2024-06-28 02:10:00"},"practice_balance":1000,"device_user_limit":2,"recharge_options_default":100,"service_email":"support@penko.co.in","mgm_config":{"switch":"1","register_reward":"6","first_charge_reward":"0","first_recharge_reward":"5","second_recharge_reward":"10","three_recharge_reward":"10","bind_invite_code_bonus_reward":"50","bind_invite_code_bonus_reward_validity":"72","recharge_bonus_reward":["50","50","50"],"recharge_bonus_reward_validity":["72","72","72"],"recharge_reminder_email_title":"MGM-Reminder from Your Friend","recharge_reminder_email_content":"Hey\uff01You haven\u2019t recharge yet? Come and get recharge bonus once complete your first deposit.","invite_excessive_email_title":"MGM-Notice","invite_excessive_email_content":"Dear Player, We are sorry to inform you that you cannot invite friends to join the Referral Billionaire Event temporarily due to your unusual invitation behavior.","reward_top_num":"8","reward_total_num":"8","recharge_amount_1":"15","recharge_amount_2":"100","recharge_amount_3":"200"},"payment_x":true,"game_lobby":{"hot":[9,10],"new":[14,15]},"join_get_bonus":10000,"user_bind_phone_reward":{"type":1,"amount":"0","bonus_finish":72},"activity_text_config":{"daily_gift":["130","130","200"],"first_recharge":["100","100"],"week_recharge":["40","20,000"],"coupon":["50","50","1500"],"mgm":["100"]},"game_version":{"forest":"86ca2","wingo":"583e2","slotAZTEC":"2ea20","slotEgypt":"967b1","slotSJB":"ca795","slotFruit":"25148","truco":"711c2","crash":"05265","slotZeus":"a48c0"},"recharge_options_new":[20,30,40,50,80,100,200,300,500,800,1000,2000,3000,5000,8000,10000,20000,30000,50000,80000],"service_telegram_07:com.slots.big":"mega2support","service_whatsapp:com.slots.big":"https:\/\/whatsapp.com\/channel\/0029VbBbCRf3AzNY3Kevpv1W","recharge_options_pay_1":[20,30,40,50,80,100,200,300,500,800,1000,2000,3000,5000,8000,10000,20000,30000,50000,80000],"recharge_options_pay_2":[20,30,40,50,80,100,200,300,500,800,1000,2000,3000,5000,8000,10000,20000,30000,50000,80000],"ab":0,"pix_config":{"account_limit_size":100,"cpf_limit_size":1},"hall_version":{"sign":"1234"},"ab_condition":{"openFlag":true,"playOpenFlag":true,"playTimes":20,"ipWhites":"15.229.81.27","ipFlag":true,"timeZoneFlag":true,"languageFlag":true},"device_bonus_times_limit":1,"recharge_amount_max":999999,"h5Url":"http:\/\/m.aphrodite777.com\/","user_register_reward":0,"service_telegram_channel:com.slots.big":"Brasil_MEGA","recharge_rate":60,"withdraw_pay_rate":0,"withdraw_system_rate":600,"recharge_first_cashback_rate":"20%","recharge_cashback_rate":"10%","service_telegram_01:com.slots.big":"mega2support","service_telegram_broker01:com.slots.big":"mega2support","service_telegram_broker09:com.slots.big":"mega2support","service_telegram_broker08:com.slots.big":"mega2support","withdraw_begin":"21:30","withdraw_end":"00:30","ip_user_limit":6,"invite_hig_reward":35,"invite_reward_distribute_time":"04:00","1service_whatsapp_business":"+447492797520,+971583054874","new_user_balance":0,"pay_callback":null,"pay_gateway":1,"shopping":[],"recharge_level":[{"amount_min":"20.00","amount_max":"29.00","rate":"0.0000","bonus_rate":"0.0000","bonus_finish":72},{"amount_min":"30.00","amount_max":"39.00","rate":"0.0000","bonus_rate":"0.0000","bonus_finish":72},{"amount_min":"40.00","amount_max":"49.00","rate":"0.0000","bonus_rate":"0.0000","bonus_finish":72},{"amount_min":"50.00","amount_max":"79.00","rate":"0.0700","bonus_rate":"0.0000","bonus_finish":72},{"amount_min":"50.00","amount_max":"99999999.00","rate":"0.2000","bonus_rate":"0.0000","bonus_finish":72},{"amount_min":"80.00","amount_max":"99.00","rate":"0.0700","bonus_rate":"0.0000","bonus_finish":72},{"amount_min":"100.00","amount_max":"199.00","rate":"0.0700","bonus_rate":"0.0000","bonus_finish":72},{"amount_min":"200.00","amount_max":"299.00","rate":"0.0700","bonus_rate":"0.0000","bonus_finish":72},{"amount_min":"300.00","amount_max":"499.00","rate":"0.0700","bonus_rate":"0.0000","bonus_finish":72},{"amount_min":"500.00","amount_max":"799.00","rate":"0.0800","bonus_rate":"0.0000","bonus_finish":72},{"amount_min":"800.00","amount_max":"999.00","rate":"0.0800","bonus_rate":"0.0000","bonus_finish":72},{"amount_min":"1000.00","amount_max":"1999.00","rate":"0.0800","bonus_rate":"0.0000","bonus_finish":72},{"amount_min":"2000.00","amount_max":"2999.00","rate":"0.0800","bonus_rate":"0.0000","bonus_finish":72},{"amount_min":"3000.00","amount_max":"4999.00","rate":"0.0900","bonus_rate":"0.0000","bonus_finish":72},{"amount_min":"5000.00","amount_max":"7999.00","rate":"0.0900","bonus_rate":"0.0000","bonus_finish":72},{"amount_min":"8000.00","amount_max":"9999.00","rate":"0.0900","bonus_rate":"0.0000","bonus_finish":72},{"amount_min":"10000.00","amount_max":"19999.00","rate":"0.1000","bonus_rate":"0.0000","bonus_finish":72},{"amount_min":"20000.00","amount_max":"29999.00","rate":"0.1000","bonus_rate":"0.0000","bonus_finish":72},{"amount_min":"30000.00","amount_max":"49999.00","rate":"0.1000","bonus_rate":"0.0000","bonus_finish":72},{"amount_min":"50000.00","amount_max":"79999.00","rate":"0.1000","bonus_rate":"0.0000","bonus_finish":72},{"amount_min":"80000.00","amount_max":"99999999.00","rate":"0.1000","bonus_rate":"0.0000","bonus_finish":72}],"control_config":{"is_review":0,"login":[1,2],"withdraw_control":0,"withdraw_rounds":0},"withdraw_config":{"amount_day":"100.00","handle_count_day":10000,"count_user_day":3,"amount_user_day":"5000.00","always_amount":"10000.00"},"currentOnline":true}}


-------------------------------------------------

GET /prod-api/year/api/yearRechargeReward HTTP/2
Host: hus3wyear.ccgamevip.com
Sec-Ch-Ua-Platform: "Windows"
Cache-Control: no-cache
Accept-Language: pt-BR,pt;q=0.9
Sec-Ch-Ua: "Not-A.Brand";v="24", "Chromium";v="146"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
Nbcx: 207587
Xutc: aphrodite777
Token: 207587:1781026736:3001:3d1022d4885108c66afee70e43c58ebc
Origin: https://ds.aphrodite777.com
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://ds.aphrodite777.com/
Accept-Encoding: gzip, deflate, br
Priority: u=1, i

HTTP/2 200 OK
Content-Type: application/json
Server: nginx/1.26.3
Date: Tue, 09 Jun 2026 17:38:57 GMT
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
Access-Control-Allow-Origin: *
X-Cache: Miss from cloudfront
Via: 1.1 72bf61aea465a7ccb624dd67744c6848.cloudfront.net (CloudFront)
X-Amz-Cf-Pop: GIG52-P3
X-Amz-Cf-Id: jhbzTJ40__Ugc7G3gHj2pBn4ZR1IAkF14hSBQ2INK-QPGFRv8TMWcw==

{"code":200,"msg":"success","data":{"id":172929,"userId":207587,"day":20260609,"reward":100,"createTime":null,"appPackageName":"com.slots.big","jiama":null,"status":0,"yearNum":4,"vipLevel":0,"times":1},"total":0}

----------------------------------------------------------

PUT /prod-api/year/api/claimYearReward HTTP/2
Host: hus3wyear.ccgamevip.com
Content-Length: 0
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: pt-BR,pt;q=0.9
Sec-Ch-Ua: "Not-A.Brand";v="24", "Chromium";v="146"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
Nbcx: 207587
Content-Type: application/x-www-form-urlencoded
Xutc: aphrodite777
Token: 207587:1781026736:3001:3d1022d4885108c66afee70e43c58ebc
Origin: https://ds.aphrodite777.com
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://ds.aphrodite777.com/
Accept-Encoding: gzip, deflate, br
Priority: u=1, i


HTTP/2 200 OK
Content-Type: application/json
Server: nginx/1.26.3
Date: Tue, 09 Jun 2026 17:48:12 GMT
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
Access-Control-Allow-Origin: *
X-Cache: Miss from cloudfront
Via: 1.1 8b63e50e0afbd78573f3ccba334f4b26.cloudfront.net (CloudFront)
X-Amz-Cf-Pop: GIG52-P3
X-Amz-Cf-Id: B_HbLlR7jajN4xhyhOQH4s0Bva1Ufk95eMg-GYVT-8I_hDUMjOmX2w==

{"code":130027,"msg":"Poderá participar neste evento após concluir a recarga.","data":null,"total":0}

----------------------------------------------------

GET /prod-api/year/api/yearRechargeReward HTTP/2
Host: hus3wyear.ccgamevip.com
Sec-Ch-Ua-Platform: "Windows"
Cache-Control: no-cache
Accept-Language: pt-BR,pt;q=0.9
Sec-Ch-Ua: "Not-A.Brand";v="24", "Chromium";v="146"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
Nbcx: 207587
Xutc: aphrodite777
Token: 207587:1781026736:3001:3d1022d4885108c66afee70e43c58ebc
Origin: https://ds.aphrodite777.com
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://ds.aphrodite777.com/
Accept-Encoding: gzip, deflate, br
Priority: u=1, i


HTTP/2 200 OK
Content-Type: application/json
Server: nginx/1.26.3
Date: Tue, 09 Jun 2026 17:48:11 GMT
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
Access-Control-Allow-Origin: *
X-Cache: Miss from cloudfront
Via: 1.1 8b63e50e0afbd78573f3ccba334f4b26.cloudfront.net (CloudFront)
X-Amz-Cf-Pop: GIG52-P3
X-Amz-Cf-Id: P6vsHTVuBpmeIVDASupiMyeK3OKaxyLdSgH7RDh8Fu6T7C9SoxTRGQ==

{"code":200,"msg":"success","data":{"id":172929,"userId":207587,"day":20260609,"reward":100,"createTime":"2026-06-09T14:38:57.000-03:00","appPackageName":"com.slots.big","jiama":0,"status":0,"yearNum":4,"vipLevel":0,"times":1},"total":0}

-----------------------------
https://ds.lucky777.mx/
--------------------------------









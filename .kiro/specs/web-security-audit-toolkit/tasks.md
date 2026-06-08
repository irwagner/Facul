# Implementation Plan: Web Security Audit Toolkit

## Overview

A implementação segue uma abordagem incremental em **Python**, priorizando a **camada de Governança** (autorização, escopo, rate limiting, auditoria e sessão) antes de qualquer camada de Execução, já que essas garantias são pré-requisito de segurança transversal: nenhuma requisição de rede pode ser despachada sem validação prévia.

A ordem das fases reflete o risco crescente do design (passivo → ativo → lógica de negócio):

1. Fundação (estrutura, modelos de dados, exceções)
2. Governança (autorização, escopo, rate limiting, auditoria, sessão)
3. Orquestração (gating de fases)
4. Descoberta de superfície e enumeração
5. Execução de checagens (passivas, ativas e Nuclei)
6. Análise (classificação e decisão)
7. Relatório
8. Integração e wiring

Os testes baseados em propriedades (PBT) usam **Hypothesis** com no mínimo **100 iterações** por propriedade (`@settings(max_examples=100)` ou superior). Cada teste de propriedade carrega a tag no formato:
`# Feature: web-security-audit-toolkit, Property {número}: {texto da propriedade}`.

Fluxos com rede, sistema de arquivos e subprocess (DNS, probing, download, Nuclei) são cobertos por testes de exemplo, integração e smoke com mocks, conforme a Estratégia de Testes do design.

## Tasks

- [x] 1. Configurar estrutura do projeto e fundação
  - [x] 1.1 Criar estrutura de pacotes e configurar ambiente de testes
    - Criar a árvore `src/toolkit/` com subpacotes `governance/`, `discovery/`, `execution/`, `execution/checks/`, `analysis/`, `analysis/classifiers/`, `reporting/` (cada um com `__init__.py`)
    - Criar `pyproject.toml` declarando dependências de runtime (`requests`/`httpx`, `dnspython`) e de teste (`pytest`, `hypothesis`)
    - Criar `tests/` e `tests/conftest.py` com estratégias Hypothesis base reutilizáveis (placeholders para `Authorization`, `Finding`, `NucleiFinding`, `SessionState`, cabeçalhos HTTP, identificadores e bundles)
    - _Requisitos: base de todos_

  - [x] 1.2 Implementar os modelos de dados como dataclasses serializáveis
    - Definir em `src/toolkit/models.py`: `Authorization`, `Target`, `Host`, `Technology`, `Endpoint`, `Finding`, `NucleiFinding`, `AttackSurfaceMap`, `Exclusion`, `SessionState`, `OperationRecord`, `AuditEvent`
    - Implementar helpers de serialização de/para JSON (`to_dict`/`from_dict`) preservando `extra` em `NucleiFinding` e datas em ISO 8601
    - _Requisitos: 1.1, 2.5, 2.6, 10.3, 11.3, 12.3_

  - [x] 1.3 Implementar a hierarquia de exceções
    - Definir em `src/toolkit/exceptions.py`: `ToolkitError`, `AuthorizationError`, `ScopeError`, `SessionPersistenceError`, `NucleiError`
    - _Requisitos: 1.2, 1.3, 1.5, 10.6, 12.3_

- [x] 2. Implementar Governança — Autorização e Escopo
  - [x] 2.1 Implementar AuthorizationManager
    - Criar `src/toolkit/governance/authorization.py` com `register`, `load`, `is_valid`, `is_expired`, `require_valid`
    - `is_valid` exige os 3 campos obrigatórios e `auth_date` a no máximo 1 ano de `now`; `is_expired` quando `now - auth_date > 1 ano`; `require_valid` lança `AuthorizationError` quando ausente/inválida
    - Persistir e carregar a autorização do arquivo de config no diretório de trabalho; em falha de escrita, abortar e propagar caminho e razão
    - _Requisitos: 1.1, 1.2, 1.3, 1.6_

  - [x] 2.2 Escrever teste de propriedade para validade/expiração de autorização
    - **Property 1: Validade e expiração da autorização**
    - **Validates: Requirements 1.2, 1.6**
    - Gerar `Authorization` com campos e datas variados; verificar bicondicional de `is_valid`/`is_expired` e que `require_valid` sempre lança quando inválida/ausente

  - [x] 2.3 Implementar ScopeValidator
    - Criar `src/toolkit/governance/scope.py` com `in_scope` (match exato de domínio, sufixo de subdomínio ou IP em CIDR) e `assert_in_scope` (lança `ScopeError` e registra `AuditEvent` com timestamp, alvo, escopo e módulo)
    - _Requisitos: 1.4, 1.5, 2.6_

  - [x] 2.4 Escrever teste de propriedade para decisão de escopo e bloqueio com log
    - **Property 2: Decisão de escopo e bloqueio com log**
    - **Validates: Requirements 1.4, 1.5**
    - Gerar listas de domínios/CIDRs autorizados e alvos dentro/fora; verificar bicondicional de `in_scope` e que `assert_in_scope` lança e registra evento para alvos fora de escopo

  - [x] 2.5 Escrever testes de exemplo para registro e falha de escrita da autorização
    - Cobrir registro com os 3 campos obrigatórios e abortar com mensagem (path + razão) quando a escrita do arquivo de config falha (mock de filesystem)
    - _Requisitos: 1.1, 1.3_

- [x] 3. Implementar Governança — Rate Limiting, Auditoria e Sessão
  - [x] 3.1 Implementar RateLimiter
    - Criar `src/toolkit/governance/rate_limiter.py` com `acquire` (token bucket) e `apply_backoff`; clamp da taxa em [1, 10] req/s e do delay em [1, 60]s (default 5)
    - _Requisitos: 3.6, 3.7_

  - [x] 3.2 Escrever teste de propriedade para limitação de taxa e cálculo de delay
    - **Property 3: Limitação de taxa e cálculo de delay**
    - **Validates: Requirements 3.6, 3.7**
    - Gerar taxas e valores de delay dentro/fora de faixa; verificar clamp em [1,10] req/s e delay em [1,60]s

  - [x] 3.3 Implementar AuditLogger
    - Criar `src/toolkit/governance/audit_logger.py` com `log` append-only e timestamp ISO 8601, mascarando payloads sensíveis no detalhe
    - _Requisitos: 1.5, 2.6, 9.6_

  - [x] 3.4 Implementar SessionManager
    - Criar `src/toolkit/session.py` com `save` e `load` do `SessionState` em JSON único no diretório de trabalho; lançar `SessionPersistenceError` em falha de IO
    - _Requisitos: 12.3, 12.4_

  - [x] 3.5 Escrever teste de propriedade para round-trip do estado de sessão
    - **Property 25: Round-trip do estado de sessão**
    - **Validates: Requirements 12.3**
    - Gerar `SessionState` completos; verificar que salvar+carregar preserva fases, findings, alvos e timestamps ISO 8601

- [x] 4. Checkpoint — Governança
  - Garantir que todos os testes passam; perguntar ao usuário em caso de dúvidas.

- [x] 5. Implementar Orquestração de Fases
  - [x] 5.1 Implementar PhaseOrchestrator
    - Criar `src/toolkit/orchestrator.py` com `start_session`, `resume_session`, `describe_phase` (objetivo, comandos e instruções de coleta) e `can_enter_phase` (gating de risco)
    - `can_enter_phase` exige confirmação se a fase é de risco médio/alto E a Fase 1 (descoberta passiva) não está concluída
    - _Requisitos: 12.1, 12.4, 12.5, 12.6_

  - [x] 5.2 Escrever teste de propriedade para gating de fases por nível de risco
    - **Property 26: Gating de fases por nível de risco**
    - **Validates: Requirements 12.6**
    - Gerar `SessionState` com/sem Fase 1 concluída e fases de níveis variados; verificar bicondicional de exigência de confirmação

  - [x] 5.3 Escrever testes de exemplo para briefings e retomada de sessão
    - Verificar conteúdo de `describe_phase` por fase e o resumo apresentado em `resume_session`
    - _Requisitos: 12.1, 12.4, 12.5_

- [x] 6. Implementar Descoberta de Superfície
  - [x] 6.1 Implementar SurfaceMapper
    - Criar `src/toolkit/discovery/surface_mapper.py` com `enumerate_subdomains` (passivo: DNS + Certificate Transparency), `identify_active_hosts` (responde a SYN/ICMP em 5s) e `build_surface_map`
    - `build_surface_map` exclui itens fora de escopo via `ScopeValidator`, registrando uma `Exclusion` (host, razão, timestamp) por exclusão
    - _Requisitos: 2.1, 2.2, 2.5, 2.6, 2.7_

  - [x] 6.2 Escrever teste de propriedade para geração do mapa de superfície
    - **Property 4: Geração do mapa de superfície exclui itens fora de escopo**
    - **Validates: Requirements 2.5, 2.6**
    - Gerar conjuntos mistos de hosts (dentro/fora de escopo); verificar que o mapa contém exatamente os hosts em escopo com portas/tecnologias preservadas e uma `Exclusion` por host excluído

  - [x] 6.3 Escrever testes de integração para enumeração passiva e probing
    - Mockar DNS/Certificate Transparency e probing de host; cobrir caso de zero subdomínios (aviso + prompt)
    - _Requisitos: 2.1, 2.2, 2.7_

  - [x] 6.4 Implementar Fingerprinter
    - Criar `src/toolkit/discovery/fingerprinter.py` com `fingerprint` identificando web server, framework e CDN por host/porta
    - _Requisitos: 2.4_

  - [x] 6.5 Escrever teste de integração para fingerprinting
    - Mockar respostas de serviço e verificar categorização das tecnologias
    - _Requisitos: 2.4_

- [x] 7. Implementar Enumeração de Endpoints
  - [x] 7.1 Implementar Enumerator
    - Criar `src/toolkit/discovery/enumerator.py` com `scan_ports` (portas fixas 80,443,8080,8443,8000,8888,9090,9443,3000,5000), `discover_paths` (wordlist ≥100 + painéis administrativos comuns), `classify_response` (200: status/tamanho/título; 301/302: path/status/Location) e `probe_parameters`
    - Integrar `RateLimiter` (máx. 10 req/s) e backoff sob HTTP 429
    - _Requisitos: 2.3, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7_

  - [x] 7.2 Escrever teste de propriedade para cobertura de paths de enumeração
    - **Property 5: Cobertura de paths de enumeração**
    - **Validates: Requirements 3.1, 3.2**
    - Gerar wordlists arbitrárias; verificar que o conjunto testado é a união da wordlist com o conjunto fixo de painéis administrativos

  - [x] 7.3 Escrever teste de propriedade para classificação de resposta
    - **Property 6: Classificação de resposta registra os campos corretos por classe de status**
    - **Validates: Requirements 3.3, 3.4**
    - Gerar respostas HTTP; verificar campos registrados para 200 e para 301/302

  - [x] 7.4 Escrever testes de exemplo para sondagem de parâmetros e config de taxa
    - Cobrir variação de um parâmetro por vez e validação dos limites de configuração de taxa/delay
    - _Requisitos: 3.5, 3.6_

- [x] 8. Checkpoint — Descoberta e Enumeração
  - Garantir que todos os testes passam; perguntar ao usuário em caso de dúvidas.

- [x] 9. Implementar Scanner — Checagens Passivas
  - [x] 9.1 Implementar verificação de source maps
    - Criar `src/toolkit/execution/checks/source_maps.py` com `check_source_maps`: busca o HTML, extrai URLs de assets e testa ≥10 paths `.map`, retornando `SourceMapResult`; valida escopo antes de cada request
    - _Requisitos: 4.1_

  - [x] 9.2 Escrever testes de exemplo para verificação de source maps
    - Mockar respostas HTTP cobrindo erros 403/500/timeout excluídos do resultado
    - _Requisitos: 4.1, 4.6_

  - [x] 9.3 Implementar download do bundle JavaScript
    - Criar `src/toolkit/execution/checks/bundle.py` com `analyze_js_bundle`: baixa arquivos `.js`, loga falhas (URL + status), pula o arquivo e continua, retornando conteúdo bruto por arquivo
    - _Requisitos: 5.1_

  - [x] 9.4 Escrever testes de exemplo para falha de download de bundle
    - Verificar que falha em um arquivo é logada e não interrompe os demais (mock de rede)
    - _Requisitos: 5.1_

  - [x] 9.5 Implementar verificação de CDN bypass
    - Criar `src/toolkit/execution/checks/cdn_bypass.py` com seleção de candidatos passivos (únicos, no máximo 5) e `check_cdn_bypass`: request direta ao IP com `Host` header, timeout 10s, marcando candidatos inacessíveis
    - _Requisitos: 6.1, 6.2_

  - [x] 9.6 Escrever teste de propriedade para limite de candidatos a IP de origem
    - **Property 11: Limite de candidatos a IP de origem**
    - **Validates: Requirements 6.1**
    - Gerar coleções de candidatos (com duplicatas); verificar que o conjunto avaliado é único e tem no máximo 5 elementos

  - [x] 9.7 Escrever testes de exemplo para request direta e candidatos inacessíveis
    - Mockar recusa/timeout e verificar marcação "unreachable" e continuidade
    - _Requisitos: 6.2_

  - [x] 9.8 Implementar verificação de cabeçalhos de segurança
    - Criar `src/toolkit/execution/checks/headers.py` com `check_security_headers`: GET com timeout 10s, extrai todos os headers; em falha de request, retorna status `check_failed`
    - _Requisitos: 7.1_

  - [x] 9.9 Escrever testes de exemplo para falha na requisição de headers
    - Verificar abortar a checagem com status `check_failed` quando a request falha (mock)
    - _Requisitos: 7.1_

- [x] 10. Implementar Scanner — Checagens Ativas
  - [x] 10.1 Implementar verificação de IDOR
    - Criar `src/toolkit/execution/checks/idor.py` com geração de variações de identificador (exatamente {+1, -1, UUID aleatório, 0, inteiro negativo}, no máximo 5) e `check_idor`: requests autenticados com o token do usuário atual; valida escopo antes de cada request
    - _Requisitos: 8.1, 8.6_

  - [x] 10.2 Escrever teste de propriedade para geração de variações de identificador
    - **Property 14: Geração e limite de variações de identificador**
    - **Validates: Requirements 8.1, 8.6**
    - Gerar identificadores inteiros e UUID; verificar que o conjunto de variações é exatamente o esperado e nunca excede 5

  - [x] 10.3 Escrever testes de exemplo para requisições autenticadas de IDOR
    - Mockar respostas e verificar montagem das requisições com token
    - _Requisitos: 8.1_

  - [x] 10.4 Implementar verificação de lógica de negócio
    - Criar `src/toolkit/execution/checks/business_logic.py` com geração de payloads (exatamente {-1, 0, 0.000000001, 9007199254740991, `"abc"`}) e `check_business_logic`: manipulação de parâmetros e teste de race condition (3 requests simultâneos, janela de 10s); registra cada request no audit log (timestamp ISO 8601, método, endpoint, payload mascarado, status, tamanho)
    - _Requisitos: 9.1, 9.3, 9.6_

  - [x] 10.5 Escrever teste de propriedade para geração de payloads de manipulação
    - **Property 17: Geração de payloads de manipulação de lógica de negócio**
    - **Validates: Requirements 9.1**
    - Gerar parâmetros numéricos; verificar que o conjunto de valores de teste é exatamente o conjunto fixo definido

  - [x] 10.6 Escrever testes de exemplo/integração para race condition
    - Verificar disparo de exatamente 3 requests simultâneos, captura dentro de 10s e log de timeouts/erros (mock)
    - _Requisitos: 9.3, 9.6_

- [x] 11. Implementar Integração com Nuclei
  - [x] 11.1 Implementar disponibilidade e execução do Nuclei
    - Criar `src/toolkit/execution/nuclei_adapter.py` com `is_available` (binário no PATH; senão, instruções por SO) e `run` (target + tags + saída JSON via subprocess; captura stdout/stderr/exit_code; lança `NucleiError` em exit ≠ 0)
    - _Requisitos: 10.1, 10.2, 10.6_

  - [x] 11.2 Escrever testes de smoke e integração para o Nuclei
    - Smoke: verificação do binário no PATH. Integração: montagem do comando e captura de saída/erro com subprocess mockado
    - _Requisitos: 10.1, 10.2, 10.6_

  - [x] 11.3 Implementar parsing, serialização e deduplicação do Nuclei
    - Adicionar a `nuclei_adapter.py`: `parse_output` (JSONL linha a linha, preservando campos não modelados em `extra`), `serialize` (re-serialização JSONL) e `deduplicate` (chave (template_id, host), mantém a primeira ocorrência e a ordem relativa)
    - _Requisitos: 10.3, 10.4_

  - [x] 11.4 Escrever teste de propriedade para deduplicação idempotente
    - **Property 21: Deduplicação idempotente de findings do Nuclei**
    - **Validates: Requirements 10.4**
    - Gerar listas de `NucleiFinding`; verificar remoção de duplicatas por (template_id, host) preservando ordem e idempotência

- [x] 12. Checkpoint — Execução
  - Garantir que todos os testes passam; perguntar ao usuário em caso de dúvidas.

- [x] 13. Implementar Análise — Classificação e Decisão
  - [x] 13.1 Implementar classificador de source maps
    - Criar `src/toolkit/analysis/classifiers/source_maps.py` com `analyze_source_maps`: confirma source map exposto (alta severidade) sse há path 200 + Content-Type `application/json` + JSON válido; senão `not_vulnerable` (confiança média); paths com erro são excluídos; extrai até 5 entradas de `sources`, truncando evidência em 200 caracteres
    - _Requisitos: 4.2, 4.3, 4.5, 4.6_

  - [x] 13.2 Escrever teste de propriedade para decisão de exposição de source map
    - **Property 7: Decisão de exposição de source map**
    - **Validates: Requirements 4.2, 4.5, 4.6**
    - Gerar combinações de (status, Content-Type, validade do corpo); verificar a decisão bicondicional e a exclusão de paths com erro

  - [x] 13.3 Escrever teste de propriedade para limites de evidência de source map
    - **Property 8: Limites de evidência de source map**
    - **Validates: Requirements 4.3**
    - Gerar campos `sources` de tamanho arbitrário; verificar no máximo 5 entradas e cada trecho com no máximo 200 caracteres

  - [x] 13.4 Implementar detector de segredos e classificador de bundle
    - Criar `src/toolkit/analysis/classifiers/secrets.py` com regexes (chave privada Ethereum `0x`+64 hex; endereço `0x`+40 hex; API key; mnemônico BIP-39 de 12/24 palavras) e `analyze_bundle_hits`: mascara o segredo (4 primeiros + `***` + 4 últimos), atribui severidade `critical` (chaves privadas) ou `high` (endereços/API keys); sem padrões → `not_vulnerable` (confiança média)
    - _Requisitos: 5.2, 5.3, 5.5_

  - [x] 13.5 Escrever teste de propriedade para detecção de segredos sem falsos positivos
    - **Property 9: Detecção de segredos correta e sem falsos positivos**
    - **Validates: Requirements 5.2, 5.5**
    - Gerar bundles com segredos injetados de formato conhecido e bundles limpos; verificar detecção do tipo correto e ausência de falsos positivos

  - [x] 13.6 Escrever teste de propriedade para mascaramento e severidade de segredos
    - **Property 10: Mascaramento e severidade de segredos detectados**
    - **Validates: Requirements 5.3**
    - Verificar que a evidência só mostra 4+4 caracteres com `***` no meio, nunca o valor completo, e a severidade correta por tipo

  - [x] 13.7 Implementar classificador de CDN bypass
    - Criar `src/toolkit/analysis/classifiers/cdn_bypass.py` com `analyze_cdn_bypass`: confirma bypass (alta severidade) sse mesmo status E tamanho do corpo via IP dentro de 10% do via CDN; sem candidatos → `not_vulnerable` (confiança baixa)
    - _Requisitos: 6.3, 6.5_

  - [x] 13.8 Escrever teste de propriedade para decisão de CDN bypass
    - **Property 12: Decisão de CDN bypass por equivalência de resposta**
    - **Validates: Requirements 6.3, 6.5**
    - Gerar pares de respostas (CDN/IP direto); verificar a decisão bicondicional por equivalência e o caso sem candidatos

  - [x] 13.9 Implementar classificador de cabeçalhos de segurança
    - Criar `src/toolkit/analysis/classifiers/headers.py` com `analyze_headers`: valida CSP (≥1 diretiva, alerta para `unsafe-inline`/`unsafe-eval`), HSTS (`max-age` ≥ 31536000), `X-Frame-Options` (DENY/SAMEORIGIN), `X-Content-Type-Options` (nosniff), `Referrer-Policy` (não-vazio), `Permissions-Policy` (≥1 diretiva); finding de severidade média para ausente/mal configurado
    - _Requisitos: 7.2, 7.3, 7.4, 7.5_

  - [x] 13.10 Escrever teste de propriedade para validação de cabeçalhos de segurança
    - **Property 13: Validação de cabeçalhos de segurança HTTP**
    - **Validates: Requirements 7.2, 7.3, 7.4, 7.5**
    - Gerar conjuntos de cabeçalhos válidos/inválidos; verificar a classificação por regra e a geração de findings de severidade média

  - [x] 13.11 Implementar classificador de IDOR
    - Criar `src/toolkit/analysis/classifiers/idor.py` com `analyze_idor`: confirma IDOR (alta severidade) sse status 200 E corpo contém campo de id de usuário (`id`/`userId`/`user_id`) diferente do autenticado; 4xx → controle de acesso ok; todas não-2xx → `inconclusive`
    - _Requisitos: 8.2, 8.3, 8.5_

  - [x] 13.12 Escrever teste de propriedade para decisão de IDOR
    - **Property 15: Decisão de IDOR**
    - **Validates: Requirements 8.2, 8.3**
    - Gerar respostas autenticadas; verificar a decisão bicondicional de IDOR e o registro de 4xx como controle de acesso funcionando

  - [x] 13.13 Escrever teste de propriedade para resultado inconclusivo de IDOR
    - **Property 16: Resultado inconclusivo de IDOR**
    - **Validates: Requirements 8.5**
    - Gerar conjuntos em que todas as respostas são não-2xx; verificar resultado `inconclusive`

  - [x] 13.14 Implementar classificador de lógica de negócio
    - Criar `src/toolkit/analysis/classifiers/business_logic.py` com `analyze_business_logic`: confirma manipulação de parâmetro (severidade crítica) sse saque negativo retorna 200 com campo de saldo/confirmação; confirma race condition (crítica) sse ≥2 de 3 respostas têm 200 com campo de saldo/confirmação
    - _Requisitos: 9.2, 9.4_

  - [x] 13.15 Escrever teste de propriedade para manipulação de parâmetro e race condition
    - **Property 18: Decisão de manipulação de parâmetro e race condition**
    - **Validates: Requirements 9.2, 9.4**
    - Gerar respostas de saque e trios de respostas; verificar a decisão bicondicional para ambos os casos
,,58
  - [x] 13.16 Implementar helpers de mascaramento de dados sensíveis
    - Criar `src/toolkit/analysis/classifiers/masking.py` com funções que reduzem evidências/payloads a nomes de campos estruturais ou valores mascarados (sem PII nem segredos em texto claro), usadas por IDOR, lógica de negócio e segredos
    - _Requisitos: 8.4, 9.5, 9.6_

  - [x] 13.17 Escrever teste de propriedade para não exposição de valores sensíveis
    - **Property 19: Invariante de não exposição de valores sensíveis**
    - **Validates: Requirements 8.4, 9.5, 9.6**
    - Gerar findings e registros de log de checagens sensíveis; verificar ausência de PII/segredos em texto claro e presença dos campos obrigatórios no registro de request de lógica de negócio

  - [x] 13.18 Implementar mapeamento de findings do Nuclei
    - Criar `src/toolkit/analysis/classifiers/nuclei.py` com `map_nuclei_findings`: converte cada `NucleiFinding` para o formato padrão `Finding` (resumo, severidade, confiança, evidência, próximos passos)
    - _Requisitos: 10.3_

  - [x] 13.19 Escrever teste de propriedade para round-trip de findings do Nuclei
    - **Property 20: Round-trip de findings do Nuclei**
    - **Validates: Requirements 10.3, 10.5**
    - Gerar `NucleiFinding` válidos (incluindo campos em `extra`); verificar que `serialize(parse(x))` é equivalente a `x`, `parse(serialize(f)) == f` e que cada entrada é mapeada para um `Finding`

  - [x] 13.20 Implementar facade do Analyzer e análise de fase
    - Criar `src/toolkit/analysis/analyzer.py` agregando os classificadores e implementando `summarize_phase` (resumo, confiança, severidade estimada, próximos passos e comandos da fase seguinte)
    - _Requisitos: 12.2_

- [x] 14. Implementar Relatório
  - [x] 14.1 Implementar ordenação e seleção de próximos passos
    - Criar `src/toolkit/reporting/reporter.py` com `order_findings` (severidade desc, depois confiança desc) e `top_next_steps` (no máximo 3, por severidade + facilidade de correção)
    - _Requisitos: 11.5, 11.6_

  - [x] 14.2 Escrever teste de propriedade para relatório como permutação ordenada
    - **Property 22: Relatório é uma permutação ordenada de todos os findings**
    - **Validates: Requirements 11.1, 11.5**
    - Gerar conjuntos de findings; verificar que a ordenação é uma permutação completa (sem perdas/adições) e não-crescente por severidade e depois confiança

  - [x] 14.3 Escrever teste de propriedade para seleção dos próximos passos prioritários
    - **Property 23: Seleção dos próximos passos prioritários**
    - **Validates: Requirements 11.6**
    - Gerar listas de findings; verificar no máximo 3 itens e que nenhum finding excluído tem prioridade estritamente maior que um incluído

  - [x] 14.4 Implementar renderização e geração do relatório
    - Adicionar a `reporter.py`: `render_markdown`, `render_html` (auto-contido, CSS inline) e `generate` (gera `.md` e `.html`; seções Capa, Sumário Executivo, Tabela de Achados, Detalhes; seção "Próximos Passos Recomendados"; trata sessão sem findings)
    - _Requisitos: 11.1, 11.2, 11.3, 11.4, 11.6, 11.7_

  - [x] 14.5 Escrever teste de propriedade para conteúdo obrigatório de finding e análise de fase
    - **Property 24: Conteúdo obrigatório de finding e análise de fase**
    - **Validates: Requirements 4.4, 6.4, 7.6, 11.3, 12.2**
    - Gerar conjuntos de findings; verificar que o detalhe renderizado contém todos os campos obrigatórios e que `summarize_phase` preenche resumo, confiança, severidade estimada e próximos passos

  - [x] 14.6 Escrever testes de exemplo para estrutura e relatório vazio
    - Verificar as seções obrigatórias, o HTML auto-contido e a nota de "nenhuma vulnerabilidade identificada" quando não há findings
    - _Requisitos: 11.2, 11.4, 11.7_

- [x] 15. Integração e Wiring
  - [x] 15.1 Conectar o orquestrador ao Analyzer e ao SessionManager
    - Implementar `PhaseOrchestrator.ingest_phase_results` delegando ao `Analyzer`, atualizando o `SessionState` e persistindo via `SessionManager` (com `OperationRecord` em ISO 8601)
    - _Requisitos: 12.2, 12.3_

  - [x] 15.2 Implementar o gateway de rede no facade do Scanner e nos módulos de execução
    - Criar `src/toolkit/execution/scanner.py` agregando as checagens; garantir que toda requisição passa por `AuthorizationManager` (válida), `ScopeValidator` (em escopo) e `RateLimiter` antes do despacho, em Scanner, Enumerator, SurfaceMapper e NucleiAdapter
    - _Requisitos: 1.2, 1.4, 1.5, 3.7_

  - [x] 15.3 Implementar o ponto de entrada (CLI) do fluxo iterativo
    - Criar `src/toolkit/cli.py` conectando as 7 fases: exibe briefing por fase, aplica gating, ingere resultados e dispara a geração do relatório
    - _Requisitos: 12.1, 12.5_

  - [x] 15.4 Escrever teste de integração do fluxo de fases ponta a ponta
    - Conduzir o fluxo via orquestrador com componentes mockados (rede/subprocess), verificando gating, persistência de estado e geração de relatório
    - _Requisitos: 12.1, 12.2, 12.3, 12.4, 12.5_

- [x] 16. Checkpoint final
  - Garantir que todos os testes passam; perguntar ao usuário em caso de dúvidas.

## Notes

- Tarefas marcadas com `*` são opcionais (testes) e podem ser puladas para um MVP mais rápido.
- Cada tarefa referencia requisitos e/ou propriedades específicas para rastreabilidade.
- Os checkpoints garantem validação incremental ao final de cada bloco lógico.
- Os testes de propriedade validam as propriedades universais de correção (Hypothesis, mínimo de 100 iterações, com a tag `# Feature: web-security-audit-toolkit, Property {número}: {texto}`).
- Testes de exemplo, integração e smoke cobrem fluxos com rede, filesystem e subprocess (DNS, probing, download, Nuclei), conforme a Estratégia de Testes do design.
- A camada de Governança é implementada antes da Execução por ser pré-requisito de segurança transversal a todas as checagens.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "1.3"] },
    { "id": 2, "tasks": ["2.1", "2.3", "3.1", "3.3", "3.4", "6.4", "11.1", "13.16"] },
    { "id": 3, "tasks": ["2.2", "2.4", "2.5", "3.2", "3.5", "5.1", "6.1", "7.1", "9.1", "9.3", "9.5", "9.8", "10.1", "10.4", "13.1", "13.4", "13.7", "13.9", "13.11", "13.14", "13.18", "14.1"] },
    { "id": 4, "tasks": ["5.2", "5.3", "6.2", "6.3", "6.5", "7.2", "7.3", "7.4", "9.2", "9.4", "9.6", "9.7", "9.9", "10.2", "10.3", "10.5", "10.6", "11.2", "11.3", "13.2", "13.3", "13.5", "13.6", "13.8", "13.10", "13.12", "13.13", "13.15", "13.17", "13.19", "13.20", "14.2", "14.3", "14.4", "15.2"] },
    { "id": 5, "tasks": ["11.4", "14.5", "14.6", "15.1"] },
    { "id": 6, "tasks": ["15.3", "15.4"] }
  ]
}
```

# Web Security Audit Toolkit — Projeto Faculdade

Toolkit de auditoria de segurança web desenvolvido como projeto de faculdade.
Aplica técnicas de pentest passivo e ativo contra um alvo autorizado
(`amizade777.com`) para identificar e documentar vulnerabilidades.

---

## Como rodar

### 1. Instalar dependências

```cmd
pip install -e .
```

### 2. Rodar a suíte de testes

```cmd
python -m pytest tests/ -q --tb=no
```

Esperado: ~763 passed, 1 skipped.

### 3. Rodar a descoberta automatizada (passiva, não precisa Burp)

```cmd
python pentest_avancado.py
```

Saída: `pentest_avancado_amizade777_com.json` com:

- subdomínios (6 fontes passivas)
- DNS sweep
- candidatos a IP de origem (bypass de CDN)
- URLs históricas (Wayback Machine + AlienVault)
- fingerprint de WAF

### 4. Testes manuais com Burp Suite

Siga o `PASSO_A_PASSO_MANUAL.md` (blocos B1-B10) e cole os resultados na
pasta `burp_tests/`.

---

## Estrutura

```
.
├── src/                  ← código do toolkit (governance, discovery, execution, ...)
├── tests/                ← suíte de testes (PBT + unitários)
├── burp_tests/           ← templates pra colar resultados dos testes manuais
├── bundles/              ← bundles JS extraídos do site (análise estática)
├── apk_extracted/        ← APK descompilado (análise mobile)
├── .kiro/                ← specs, requirements, design, memória de sessão
├── PASSO_A_PASSO_MANUAL.md   ← guia detalhado dos testes manuais com Burp
├── CONTEXTO_PROJETO.md       ← contexto técnico completo do alvo
├── RELATORIO_FINAL.md        ← relatório de vulnerabilidades encontradas
└── pentest_avancado.py       ← orquestrador da fase passiva
```

---

## Documentação

- **`PASSO_A_PASSO_MANUAL.md`** — guia passo a passo dos testes manuais
  com Burp Suite (B0 a B10). Tem desde a configuração do proxy até
  payloads de SQLi, NoSQLi, race condition e bypass de CDN.
- **`CONTEXTO_PROJETO.md`** — dados confirmados do alvo, timeline de
  achados, vulnerabilidades pendentes, arquitetura do site.
- **`RELATORIO_FINAL.md`** — relatório final com cada vulnerabilidade
  catalogada (V-2026-XXX).
- **`burp_tests/README.md`** — convenção de preenchimento dos testes
  manuais.

---

## Aviso legal

Este projeto é parte de um trabalho acadêmico com **autorização explícita
do responsável pelo alvo**. Não use os scripts deste repositório contra
sistemas que você não tem permissão para testar.

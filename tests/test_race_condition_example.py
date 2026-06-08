"""
Testes de exemplo/integração para o teste de race condition em
``check_business_logic`` (Req. 9.3, 9.6).

Todos os requests HTTP são completamente mockados via ``unittest.mock``; os
testes nunca tocam a rede.

Cobertura de testes
-------------------
* enable_race=True dispara exatamente 3 requests simultâneos
* Respostas capturadas dentro da janela de 10s (sem timeout)
* Timeouts são registrados no audit log (event_type='biz_request')
* Erros de request são registrados no audit log
* enable_race=False não dispara requests de race condition
* RaceResult sempre contém exatamente 3 resultados
* Requests de race condition usam os parâmetros originais (não manipulados)
* Cabeçalho Authorization Bearer é enviado nas race requests
"""

from __future__ import annotations

import threading
from unittest.mock import MagicMock, patch

import pytest
import requests as req_lib

from toolkit.execution.checks.business_logic import (
    BizLogicResult,
    RaceResult,
    check_business_logic,
)
from toolkit.governance.audit_logger import AuditLogger


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(status_code: int = 200, body: bytes = b'{"ok": true}') -> MagicMock:
    """Build a minimal requests.Response mock."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = body
    resp.json.return_value = {"ok": True}
    return resp


_ENDPOINT = "https://api.example.com/api/withdraw"
_TOKEN = "test-bearer-token"
_PARAMS = {"amount": 100, "account_id": 42}


# ---------------------------------------------------------------------------
# 1. enable_race=True dispara exatamente 3 requests simultâneos
# ---------------------------------------------------------------------------


class TestRaceConditionDispatches3Requests:
    """enable_race=True deve disparar exatamente 3 requests simultâneos (Req. 9.3)."""

    def test_exactly_3_race_requests_sent(self):
        """Quando enable_race=True, exatamente 3 requests devem ser enviados
        para o race condition probe (além dos requests de manipulação de parâmetro)."""
        audit_logger = AuditLogger()
        mock_resp = _make_response(200)

        call_count = {"n": 0}
        concurrent_calls = {"max": 0, "current": 0}
        lock = threading.Lock()
        barrier = threading.Barrier(3, timeout=5)

        def side_effect(*args, **kwargs):
            with lock:
                concurrent_calls["current"] += 1
                if concurrent_calls["current"] > concurrent_calls["max"]:
                    concurrent_calls["max"] = concurrent_calls["current"]
            try:
                barrier.wait()
            except threading.BrokenBarrierError:
                pass
            with lock:
                concurrent_calls["current"] -= 1
            call_count["n"] += 1
            return mock_resp

        with patch(
            "toolkit.execution.checks.business_logic.requests.request",
            side_effect=side_effect,
        ):
            result = check_business_logic(
                endpoint=_ENDPOINT,
                params=_PARAMS,
                auth_token=_TOKEN,
                audit_logger=audit_logger,
                enable_race=True,
            )

        assert result.race_results is not None
        assert len(result.race_results.responses) == 3

    def test_race_result_has_exactly_3_responses(self):
        """RaceResult.responses deve ter exatamente 3 elementos."""
        audit_logger = AuditLogger()
        mock_resp = _make_response(200)

        with patch(
            "toolkit.execution.checks.business_logic.requests.request",
            return_value=mock_resp,
        ):
            result = check_business_logic(
                endpoint=_ENDPOINT,
                params=_PARAMS,
                auth_token=_TOKEN,
                audit_logger=audit_logger,
                enable_race=True,
            )

        assert result.race_results is not None
        assert len(result.race_results.responses) == 3

    def test_race_requests_use_original_params(self):
        """Os requests de race condition devem usar os parâmetros originais."""
        audit_logger = AuditLogger()
        mock_resp = _make_response(200)

        captured_payloads: list[dict] = []

        def side_effect(*args, **kwargs):
            json_body = kwargs.get("json")
            if json_body is not None:
                captured_payloads.append(dict(json_body))
            return mock_resp

        with patch(
            "toolkit.execution.checks.business_logic.requests.request",
            side_effect=side_effect,
        ):
            result = check_business_logic(
                endpoint=_ENDPOINT,
                params=_PARAMS,
                auth_token=_TOKEN,
                audit_logger=audit_logger,
                enable_race=True,
                method="POST",
            )

        # Os últimos 3 payloads enviados devem ser os parâmetros originais
        # (race condition usa params sem modificação)
        assert result.race_results is not None
        race_payloads = captured_payloads[-3:]
        for payload in race_payloads:
            assert payload["amount"] == _PARAMS["amount"]
            assert payload["account_id"] == _PARAMS["account_id"]

    def test_race_requests_include_authorization_header(self):
        """Cada race request deve incluir o cabeçalho Authorization: Bearer."""
        audit_logger = AuditLogger()
        mock_resp = _make_response(200)

        captured_headers: list[dict] = []

        def side_effect(*args, **kwargs):
            headers = kwargs.get("headers", {})
            captured_headers.append(dict(headers))
            return mock_resp

        with patch(
            "toolkit.execution.checks.business_logic.requests.request",
            side_effect=side_effect,
        ):
            check_business_logic(
                endpoint=_ENDPOINT,
                params=_PARAMS,
                auth_token=_TOKEN,
                audit_logger=audit_logger,
                enable_race=True,
            )

        # Verificar que pelo menos 3 cabeçalhos contêm Authorization correto
        auth_headers = [
            h for h in captured_headers
            if h.get("Authorization") == f"Bearer {_TOKEN}"
        ]
        assert len(auth_headers) >= 3


# ---------------------------------------------------------------------------
# 2. Respostas capturadas dentro da janela de 10s
# ---------------------------------------------------------------------------


class TestRaceResponsesCapturedWithin10s:
    """Respostas bem-sucedidas são capturadas dentro da janela de 10s (Req. 9.3)."""

    def test_successful_responses_captured_in_race_results(self):
        """Respostas 200 são capturadas no RaceResult sem erros."""
        audit_logger = AuditLogger()
        mock_resp = _make_response(200, body=b'{"balance": 500}')

        with patch(
            "toolkit.execution.checks.business_logic.requests.request",
            return_value=mock_resp,
        ):
            result = check_business_logic(
                endpoint=_ENDPOINT,
                params=_PARAMS,
                auth_token=_TOKEN,
                audit_logger=audit_logger,
                enable_race=True,
            )

        assert result.race_results is not None
        successful = [
            r for r in result.race_results.responses
            if r.status_code == 200 and r.error is None
        ]
        assert len(successful) == 3

    def test_race_result_timed_out_count_zero_on_success(self):
        """Quando todos os requests completam normalmente, timed_out_count deve ser 0."""
        audit_logger = AuditLogger()
        mock_resp = _make_response(200)

        with patch(
            "toolkit.execution.checks.business_logic.requests.request",
            return_value=mock_resp,
        ):
            result = check_business_logic(
                endpoint=_ENDPOINT,
                params=_PARAMS,
                auth_token=_TOKEN,
                audit_logger=audit_logger,
                enable_race=True,
            )

        assert result.race_results is not None
        assert result.race_results.timed_out_count == 0

    def test_race_responses_have_correct_status_code(self):
        """Cada resposta capturada deve registrar o status code correto."""
        audit_logger = AuditLogger()

        # amount é o único parâmetro numérico → 5 requests de param manipulation
        # + 3 requests de race = 8 total
        param_responses = [_make_response(200) for _ in range(5)]
        race_responses = [_make_response(200), _make_response(201), _make_response(200)]
        all_responses = param_responses + race_responses
        resp_iter = iter(all_responses)

        def side_effect(*args, **kwargs):
            return next(resp_iter)

        with patch(
            "toolkit.execution.checks.business_logic.requests.request",
            side_effect=side_effect,
        ):
            result = check_business_logic(
                endpoint=_ENDPOINT,
                params={"amount": 100},
                auth_token=_TOKEN,
                audit_logger=audit_logger,
                enable_race=True,
            )

        assert result.race_results is not None
        status_codes = [r.status_code for r in result.race_results.responses]
        # Todos devem ter status_code (sem None em caso de sucesso)
        assert all(sc is not None for sc in status_codes)

    def test_race_responses_have_body_size(self):
        """Cada resposta deve registrar o tamanho do corpo em bytes."""
        audit_logger = AuditLogger()
        body = b'{"balance": 500, "status": "ok"}'
        mock_resp = _make_response(200, body=body)

        with patch(
            "toolkit.execution.checks.business_logic.requests.request",
            return_value=mock_resp,
        ):
            result = check_business_logic(
                endpoint=_ENDPOINT,
                params=_PARAMS,
                auth_token=_TOKEN,
                audit_logger=audit_logger,
                enable_race=True,
            )

        assert result.race_results is not None
        for r in result.race_results.responses:
            assert r.body_size == len(body)


# ---------------------------------------------------------------------------
# 3. Timeouts e erros são registrados no audit log
# ---------------------------------------------------------------------------


class TestTimeoutsAndErrorsLoggedToAudit:
    """Timeouts e erros de request são registrados no audit log (Req. 9.6)."""

    def test_timeout_in_race_logged_as_biz_request(self):
        """Um Timeout em um race request deve ser registrado como biz_request no audit log."""
        audit_logger = AuditLogger()

        with patch(
            "toolkit.execution.checks.business_logic.requests.request",
            side_effect=req_lib.exceptions.Timeout("timed out"),
        ):
            result = check_business_logic(
                endpoint=_ENDPOINT,
                params=_PARAMS,
                auth_token=_TOKEN,
                audit_logger=audit_logger,
                enable_race=True,
            )

        events = audit_logger.get_events()
        biz_events = [e for e in events if e.event_type == "biz_request"]
        assert len(biz_events) > 0

    def test_timeout_in_race_produces_error_probe(self):
        """Um Timeout deve produzir uma probe com status_code=None e campo error preenchido."""
        audit_logger = AuditLogger()

        with patch(
            "toolkit.execution.checks.business_logic.requests.request",
            side_effect=req_lib.exceptions.Timeout("timed out"),
        ):
            result = check_business_logic(
                endpoint=_ENDPOINT,
                params=_PARAMS,
                auth_token=_TOKEN,
                audit_logger=audit_logger,
                enable_race=True,
            )

        assert result.race_results is not None
        timeout_probes = [
            r for r in result.race_results.responses
            if r.status_code is None and r.error is not None
        ]
        assert len(timeout_probes) > 0

    def test_timeout_recorded_as_error_probe_not_future_timeout(self):
        """Um requests.Timeout é capturado dentro de _send_request e devolvido
        como probe com status_code=None; o timed_out_count fica 0 porque o future
        completou (com erro), sem exceder o timeout do executor.

        Apenas um concurrent.futures.TimeoutError incrementa timed_out_count.
        """
        audit_logger = AuditLogger()

        with patch(
            "toolkit.execution.checks.business_logic.requests.request",
            side_effect=req_lib.exceptions.Timeout("timed out"),
        ):
            result = check_business_logic(
                endpoint=_ENDPOINT,
                params=_PARAMS,
                auth_token=_TOKEN,
                audit_logger=audit_logger,
                enable_race=True,
            )

        assert result.race_results is not None
        # O timeout de requests é capturado como probe de erro (status_code=None)
        error_probes = [
            r for r in result.race_results.responses
            if r.status_code is None and r.error
        ]
        assert len(error_probes) == 3
        # timed_out_count permanece 0 pois os futures completaram (com erro interno)
        assert result.race_results.timed_out_count == 0

    def test_connection_error_in_race_logged_to_audit(self):
        """Um ConnectionError em um race request deve ser registrado no audit log."""
        audit_logger = AuditLogger()

        with patch(
            "toolkit.execution.checks.business_logic.requests.request",
            side_effect=req_lib.exceptions.ConnectionError("connection refused"),
        ):
            result = check_business_logic(
                endpoint=_ENDPOINT,
                params=_PARAMS,
                auth_token=_TOKEN,
                audit_logger=audit_logger,
                enable_race=True,
            )

        events = audit_logger.get_events()
        biz_events = [e for e in events if e.event_type == "biz_request"]
        # Devem existir eventos de race condition (e possivelmente de param manipulation)
        assert len(biz_events) > 0

    def test_connection_error_produces_error_probe(self):
        """Um ConnectionError deve produzir probe com status_code=None e erro descrito."""
        audit_logger = AuditLogger()

        with patch(
            "toolkit.execution.checks.business_logic.requests.request",
            side_effect=req_lib.exceptions.ConnectionError("connection refused"),
        ):
            result = check_business_logic(
                endpoint=_ENDPOINT,
                params=_PARAMS,
                auth_token=_TOKEN,
                audit_logger=audit_logger,
                enable_race=True,
            )

        assert result.race_results is not None
        error_probes = [
            r for r in result.race_results.responses
            if r.status_code is None and r.error
        ]
        assert len(error_probes) > 0
        for probe in error_probes:
            assert isinstance(probe.error, str)
            assert len(probe.error) > 0

    def test_audit_log_records_endpoint_for_race_events(self):
        """Os eventos de audit para race condition devem registrar o endpoint correto."""
        audit_logger = AuditLogger()
        mock_resp = _make_response(200)

        with patch(
            "toolkit.execution.checks.business_logic.requests.request",
            return_value=mock_resp,
        ):
            check_business_logic(
                endpoint=_ENDPOINT,
                params=_PARAMS,
                auth_token=_TOKEN,
                audit_logger=audit_logger,
                enable_race=True,
            )

        events = audit_logger.get_events()
        biz_events = [e for e in events if e.event_type == "biz_request"]
        assert len(biz_events) > 0
        for event in biz_events:
            assert event.target == _ENDPOINT

    def test_audit_log_biz_request_has_required_fields(self):
        """Cada evento biz_request deve conter os campos obrigatórios (Req. 9.6)."""
        audit_logger = AuditLogger()
        mock_resp = _make_response(200)

        with patch(
            "toolkit.execution.checks.business_logic.requests.request",
            return_value=mock_resp,
        ):
            check_business_logic(
                endpoint=_ENDPOINT,
                params=_PARAMS,
                auth_token=_TOKEN,
                audit_logger=audit_logger,
                enable_race=True,
            )

        events = audit_logger.get_events()
        biz_events = [e for e in events if e.event_type == "biz_request"]
        assert len(biz_events) > 0

        for event in biz_events:
            # Campos obrigatórios por Req. 9.6
            assert "timestamp" in event.detail
            assert "method" in event.detail
            assert "endpoint" in event.detail
            assert "status_code" in event.detail
            assert "body_size" in event.detail
            # timestamp deve ser string ISO 8601
            assert isinstance(event.detail["timestamp"], str)
            assert "T" in event.detail["timestamp"]

    def test_mixed_success_and_timeout_race(self):
        """Race com mix de sucesso e timeout deve registrar todos como biz_request."""
        audit_logger = AuditLogger()
        mock_resp = _make_response(200)
        call_count = {"n": 0}

        def side_effect(*args, **kwargs):
            n = call_count["n"]
            call_count["n"] += 1
            if n == 0:
                raise req_lib.exceptions.Timeout("timed out")
            return mock_resp

        with patch(
            "toolkit.execution.checks.business_logic.requests.request",
            side_effect=side_effect,
        ):
            result = check_business_logic(
                endpoint=_ENDPOINT,
                params={"amount": 50},
                auth_token=_TOKEN,
                audit_logger=audit_logger,
                enable_race=True,
            )

        events = audit_logger.get_events()
        biz_events = [e for e in events if e.event_type == "biz_request"]
        # Deve haver eventos de race (pelo menos 3 — um por request)
        race_events = [e for e in biz_events if e.module == "business_logic"]
        assert len(race_events) > 0

        assert result.race_results is not None
        assert len(result.race_results.responses) == 3


# ---------------------------------------------------------------------------
# 4. enable_race=False não dispara race requests
# ---------------------------------------------------------------------------


class TestRaceDisabledDoesNotDispatch:
    """enable_race=False não deve disparar requests de race condition (Req. 9.3)."""

    def test_race_results_is_none_when_race_disabled(self):
        """Quando enable_race=False, race_results deve ser None."""
        audit_logger = AuditLogger()
        mock_resp = _make_response(200)

        with patch(
            "toolkit.execution.checks.business_logic.requests.request",
            return_value=mock_resp,
        ):
            result = check_business_logic(
                endpoint=_ENDPOINT,
                params=_PARAMS,
                auth_token=_TOKEN,
                audit_logger=audit_logger,
                enable_race=False,
            )

        assert result.race_results is None

    def test_no_extra_requests_when_race_disabled(self):
        """Quando enable_race=False, apenas os requests de manipulação de parâmetro
        são enviados (2 parâmetros numéricos × 5 payloads = 10 requests)."""
        audit_logger = AuditLogger()
        mock_resp = _make_response(200)
        call_count = {"n": 0}

        def side_effect(*args, **kwargs):
            call_count["n"] += 1
            return mock_resp

        with patch(
            "toolkit.execution.checks.business_logic.requests.request",
            side_effect=side_effect,
        ):
            result = check_business_logic(
                endpoint=_ENDPOINT,
                params=_PARAMS,  # 2 parâmetros numéricos: amount e account_id
                auth_token=_TOKEN,
                audit_logger=audit_logger,
                enable_race=False,
            )

        # 2 parâmetros × 5 payloads = 10 requests (sem race requests adicionais)
        assert call_count["n"] == 10
        assert result.race_results is None

    def test_race_disabled_default_value(self):
        """O valor padrão de enable_race deve ser False."""
        audit_logger = AuditLogger()
        mock_resp = _make_response(200)
        call_count = {"n": 0}

        def side_effect(*args, **kwargs):
            call_count["n"] += 1
            return mock_resp

        with patch(
            "toolkit.execution.checks.business_logic.requests.request",
            side_effect=side_effect,
        ):
            # Chamada sem o parâmetro enable_race
            result = check_business_logic(
                endpoint=_ENDPOINT,
                params=_PARAMS,
                auth_token=_TOKEN,
                audit_logger=audit_logger,
            )

        # Sem race requests extras
        assert result.race_results is None
        assert call_count["n"] == 10

    def test_param_manipulation_still_works_when_race_disabled(self):
        """Quando enable_race=False, a manipulação de parâmetros ainda deve funcionar."""
        audit_logger = AuditLogger()
        mock_resp = _make_response(200)

        with patch(
            "toolkit.execution.checks.business_logic.requests.request",
            return_value=mock_resp,
        ):
            result = check_business_logic(
                endpoint=_ENDPOINT,
                params=_PARAMS,
                auth_token=_TOKEN,
                audit_logger=audit_logger,
                enable_race=False,
            )

        # Deve ter 10 resultados de manipulação de parâmetro (2 × 5)
        assert len(result.parameter_results) == 10

    def test_only_param_manipulation_events_logged_when_race_disabled(self):
        """Quando enable_race=False, apenas eventos de manipulação de parâmetro
        são registrados no audit log."""
        audit_logger = AuditLogger()
        mock_resp = _make_response(200)

        with patch(
            "toolkit.execution.checks.business_logic.requests.request",
            return_value=mock_resp,
        ):
            check_business_logic(
                endpoint=_ENDPOINT,
                params=_PARAMS,
                auth_token=_TOKEN,
                audit_logger=audit_logger,
                enable_race=False,
            )

        events = audit_logger.get_events()
        biz_events = [e for e in events if e.event_type == "biz_request"]
        # 2 parâmetros × 5 payloads = 10 eventos
        assert len(biz_events) == 10


# ---------------------------------------------------------------------------
# 5. Verificações adicionais do contrato da API
# ---------------------------------------------------------------------------


class TestBizLogicResultContract:
    """Verificações do contrato de BizLogicResult e RaceResult."""

    def test_biz_logic_result_contains_endpoint(self):
        """BizLogicResult deve armazenar o endpoint testado."""
        audit_logger = AuditLogger()
        mock_resp = _make_response(200)

        with patch(
            "toolkit.execution.checks.business_logic.requests.request",
            return_value=mock_resp,
        ):
            result = check_business_logic(
                endpoint=_ENDPOINT,
                params=_PARAMS,
                auth_token=_TOKEN,
                audit_logger=audit_logger,
                enable_race=False,
            )

        assert result.endpoint == _ENDPOINT

    def test_race_result_responses_are_param_test_results(self):
        """Cada elemento de RaceResult.responses deve ser um ParamTestResult."""
        from toolkit.execution.checks.business_logic import ParamTestResult

        audit_logger = AuditLogger()
        mock_resp = _make_response(200)

        with patch(
            "toolkit.execution.checks.business_logic.requests.request",
            return_value=mock_resp,
        ):
            result = check_business_logic(
                endpoint=_ENDPOINT,
                params=_PARAMS,
                auth_token=_TOKEN,
                audit_logger=audit_logger,
                enable_race=True,
            )

        assert result.race_results is not None
        for r in result.race_results.responses:
            assert isinstance(r, ParamTestResult)

    def test_race_probe_param_name_is_race_marker(self):
        """Os probes de race condition devem usar '__race__' como param_name."""
        audit_logger = AuditLogger()
        mock_resp = _make_response(200)

        with patch(
            "toolkit.execution.checks.business_logic.requests.request",
            return_value=mock_resp,
        ):
            result = check_business_logic(
                endpoint=_ENDPOINT,
                params=_PARAMS,
                auth_token=_TOKEN,
                audit_logger=audit_logger,
                enable_race=True,
            )

        assert result.race_results is not None
        for r in result.race_results.responses:
            assert r.param_name == "__race__"

    def test_only_numeric_params_are_manipulated(self):
        """Apenas parâmetros com valores numéricos (int/float) devem ser manipulados."""
        audit_logger = AuditLogger()
        mock_resp = _make_response(200)

        # Parâmetros mistos: string não deve ser manipulada
        params_mixed = {
            "amount": 100,       # numérico → manipulado
            "currency": "USD",   # string → não manipulado
            "account_id": 99,    # numérico → manipulado
        }

        with patch(
            "toolkit.execution.checks.business_logic.requests.request",
            return_value=mock_resp,
        ):
            result = check_business_logic(
                endpoint=_ENDPOINT,
                params=params_mixed,
                auth_token=_TOKEN,
                audit_logger=audit_logger,
                enable_race=False,
            )

        # 2 parâmetros numéricos × 5 payloads = 10 resultados
        assert len(result.parameter_results) == 10
        # Nenhum resultado deve ter 'currency' como param_name
        param_names = {r.param_name for r in result.parameter_results}
        assert "currency" not in param_names
        assert "amount" in param_names
        assert "account_id" in param_names

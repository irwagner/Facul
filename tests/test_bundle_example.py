"""
Testes de exemplo para o download do bundle JavaScript (Req. 5.1).

Todas as requisições HTTP são completamente mockadas via ``unittest.mock``;
os testes nunca acessam a rede.

Cobertura
---------
* Fetch do HTML com sucesso → URLs de assets .js extraídas e baixadas
* Download bem-sucedido → content preenchido, error=None
* Resposta HTTP não-200 → falha logada (URL + status), arquivo ignorado, demais continuam
* Timeout de conexão → falha logada, arquivo ignorado, demais continuam
* Erro de conexão → falha logada, arquivo ignorado, demais continuam
* Múltiplos arquivos: falha em um não interrompe os demais (Req. 5.1)
* Falha no fetch do HTML → retorna lista vazia (degradação graciosa)
* BundleFile.error contém URL e status na falha
* BundleHit.is_success funciona corretamente
* analyze_js_bundle com AuditLogger loga falhas como AuditEvents
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests as req_lib

from toolkit.execution.checks.bundle import (
    BundleFile,
    BundleHit,
    analyze_js_bundle,
    fetch_bundle_hits,
)
from toolkit.governance.audit_logger import AuditLogger


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BASE_URL = "https://example.com"


def _make_response(
    status_code: int = 200,
    body: str = "",
    headers: dict[str, str] | None = None,
) -> MagicMock:
    """Constrói um mock mínimo de requests.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = body
    headers_dict = headers or {}
    resp.headers = MagicMock()
    resp.headers.get = lambda key, default=None: headers_dict.get(key, default)
    return resp


def _html_with_scripts(*asset_paths: str) -> str:
    """Retorna uma página HTML mínima referenciando os .js informados."""
    tags = "".join(f'<script src="{p}"></script>' for p in asset_paths)
    return f"<html><head>{tags}</head><body></body></html>"


# ---------------------------------------------------------------------------
# 1. BundleHit dataclass
# ---------------------------------------------------------------------------

class TestBundleHit:
    """BundleHit.is_success se comporta corretamente."""

    def test_is_success_true_when_content_and_no_error(self):
        hit = BundleHit(url="https://ex.com/a.js", content="var x=1;", status_code=200, error_message=None)
        assert hit.is_success is True

    def test_is_success_false_when_no_content(self):
        hit = BundleHit(url="https://ex.com/a.js", content=None, status_code=404, error_message="HTTP 404")
        assert hit.is_success is False

    def test_is_success_false_when_error_message_set(self):
        hit = BundleHit(url="https://ex.com/a.js", content=None, status_code=None, error_message="Timeout")
        assert hit.is_success is False

    def test_fields_accessible(self):
        hit = BundleHit(url="https://ex.com/a.js", content="js", status_code=200, error_message=None)
        assert hit.url == "https://ex.com/a.js"
        assert hit.content == "js"
        assert hit.status_code == 200
        assert hit.error_message is None


# ---------------------------------------------------------------------------
# 2. Downloads bem-sucedidos
# ---------------------------------------------------------------------------

class TestSuccessfulDownload:
    """analyze_js_bundle retorna BundleFile com content para downloads bem-sucedidos."""

    def test_single_js_asset_downloaded(self):
        """Uma página com um asset .js → resultado contém esse URL com o conteúdo."""
        html_body = _html_with_scripts("/assets/app.js")
        html_resp = _make_response(200, body=html_body)
        js_content = "var app = {};"
        js_resp = _make_response(200, body=js_content)

        with patch(
            "toolkit.execution.checks.bundle.requests.get",
            side_effect=[html_resp, js_resp],
        ):
            result = analyze_js_bundle(BASE_URL)

        assert len(result) == 1
        bundle = result[0]
        assert isinstance(bundle, BundleFile)
        assert bundle.url.endswith("app.js")
        assert bundle.content == js_content
        assert bundle.error is None

    def test_multiple_js_assets_all_downloaded(self):
        """Uma página com múltiplos assets .js → todos são baixados e retornados."""
        html_body = _html_with_scripts("/assets/app.js", "/assets/vendor.js")
        html_resp = _make_response(200, body=html_body)
        app_js = _make_response(200, body="var app = {};")
        vendor_js = _make_response(200, body="var vendor = {};")

        with patch(
            "toolkit.execution.checks.bundle.requests.get",
            side_effect=[html_resp, app_js, vendor_js],
        ):
            result = analyze_js_bundle(BASE_URL)

        assert len(result) == 2
        assert all(isinstance(f, BundleFile) for f in result)
        assert all(f.content is not None for f in result)

    def test_return_type_is_list_of_bundle_file(self):
        """O tipo de retorno é list[BundleFile]."""
        html_body = _html_with_scripts("/assets/main.js")
        html_resp = _make_response(200, body=html_body)
        js_resp = _make_response(200, body="var x = 1;")

        with patch(
            "toolkit.execution.checks.bundle.requests.get",
            side_effect=[html_resp, js_resp],
        ):
            result = analyze_js_bundle(BASE_URL)

        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, BundleFile)

    def test_absolute_url_in_bundle_file(self):
        """A URL em BundleFile é absoluta (começa com https://)."""
        html_body = _html_with_scripts("/assets/chunk.js")
        html_resp = _make_response(200, body=html_body)
        js_resp = _make_response(200, body="var chunk = {};")

        with patch(
            "toolkit.execution.checks.bundle.requests.get",
            side_effect=[html_resp, js_resp],
        ):
            result = analyze_js_bundle(BASE_URL)

        assert len(result) == 1
        assert result[0].url.startswith("https://")


# ---------------------------------------------------------------------------
# 3. Resposta HTTP não-200 — tratamento de falhas (Req. 5.1)
# ---------------------------------------------------------------------------

class TestNon200Response:
    """Respostas não-200 são logadas e o arquivo é ignorado; os demais continuam."""

    def test_404_bundle_file_has_error_and_no_content(self):
        """Resposta 404 → BundleFile com error preenchido e content=None."""
        html_body = _html_with_scripts("/assets/missing.js")
        html_resp = _make_response(200, body=html_body)
        not_found = _make_response(404)

        with patch(
            "toolkit.execution.checks.bundle.requests.get",
            side_effect=[html_resp, not_found],
        ):
            result = analyze_js_bundle(BASE_URL)

        assert len(result) == 1
        bundle = result[0]
        assert bundle.content is None
        assert bundle.error is not None
        assert "404" in bundle.error

    def test_403_bundle_file_has_error_and_no_content(self):
        """Resposta 403 → BundleFile com error preenchido e content=None."""
        html_body = _html_with_scripts("/assets/protected.js")
        html_resp = _make_response(200, body=html_body)
        forbidden = _make_response(403)

        with patch(
            "toolkit.execution.checks.bundle.requests.get",
            side_effect=[html_resp, forbidden],
        ):
            result = analyze_js_bundle(BASE_URL)

        assert len(result) == 1
        assert result[0].content is None
        assert result[0].error is not None
        assert "403" in result[0].error

    def test_500_bundle_file_has_error_and_no_content(self):
        """Resposta 500 → BundleFile com error preenchido e content=None."""
        html_body = _html_with_scripts("/assets/error.js")
        html_resp = _make_response(200, body=html_body)
        server_error = _make_response(500)

        with patch(
            "toolkit.execution.checks.bundle.requests.get",
            side_effect=[html_resp, server_error],
        ):
            result = analyze_js_bundle(BASE_URL)

        assert len(result) == 1
        assert result[0].content is None
        assert result[0].error is not None
        assert "500" in result[0].error

    def test_failed_file_does_not_stop_others(self):
        """
        Quando um arquivo falha (não-200), os demais ainda são baixados
        (Req. 5.1 — ignorar e continuar).
        """
        html_body = _html_with_scripts("/assets/bad.js", "/assets/good.js")
        html_resp = _make_response(200, body=html_body)
        bad_resp = _make_response(404)
        good_resp = _make_response(200, body="var good = true;")

        with patch(
            "toolkit.execution.checks.bundle.requests.get",
            side_effect=[html_resp, bad_resp, good_resp],
        ):
            result = analyze_js_bundle(BASE_URL)

        # Dois BundleFile retornados: um com erro, um com sucesso
        assert len(result) == 2
        failed = [f for f in result if f.content is None]
        succeeded = [f for f in result if f.content is not None]
        assert len(failed) == 1
        assert len(succeeded) == 1
        assert succeeded[0].content == "var good = true;"

    def test_fetch_bundle_hits_records_failure_details(self):
        """fetch_bundle_hits retorna BundleHit com status_code e error_message para não-200."""
        html_body = _html_with_scripts("/assets/missing.js")
        html_resp = _make_response(200, body=html_body)
        not_found = _make_response(404)

        with patch(
            "toolkit.execution.checks.bundle.requests.get",
            side_effect=[html_resp, not_found],
        ):
            hits = fetch_bundle_hits(BASE_URL)

        assert len(hits) == 1
        hit = hits[0]
        assert hit.status_code == 404
        assert hit.content is None
        assert hit.error_message is not None
        assert "404" in hit.error_message


# ---------------------------------------------------------------------------
# 4. Erros de conexão (timeout, conexão recusada) — Req. 5.1
# ---------------------------------------------------------------------------

class TestConnectionErrors:
    """Erros de conexão são logados; o arquivo é ignorado e os demais continuam."""

    def test_timeout_bundle_file_has_error_and_no_content(self):
        """Timeout no download → BundleFile com error e content=None."""
        html_body = _html_with_scripts("/assets/slow.js")
        html_resp = _make_response(200, body=html_body)

        with patch(
            "toolkit.execution.checks.bundle.requests.get",
            side_effect=[html_resp, req_lib.exceptions.Timeout("timed out")],
        ):
            result = analyze_js_bundle(BASE_URL)

        assert len(result) == 1
        assert result[0].content is None
        assert result[0].error is not None

    def test_connection_error_bundle_file_has_error_and_no_content(self):
        """Erro de conexão no download → BundleFile com error e content=None."""
        html_body = _html_with_scripts("/assets/unreachable.js")
        html_resp = _make_response(200, body=html_body)

        with patch(
            "toolkit.execution.checks.bundle.requests.get",
            side_effect=[
                html_resp,
                req_lib.exceptions.ConnectionError("refused"),
            ],
        ):
            result = analyze_js_bundle(BASE_URL)

        assert len(result) == 1
        assert result[0].content is None
        assert result[0].error is not None

    def test_timeout_does_not_stop_remaining_files(self):
        """
        Timeout em um arquivo não aborta o processamento; os demais
        ainda são baixados (Req. 5.1).
        """
        html_body = _html_with_scripts("/assets/slow.js", "/assets/fast.js")
        html_resp = _make_response(200, body=html_body)
        fast_resp = _make_response(200, body="var fast = true;")

        with patch(
            "toolkit.execution.checks.bundle.requests.get",
            side_effect=[
                html_resp,
                req_lib.exceptions.Timeout("timed out"),
                fast_resp,
            ],
        ):
            result = analyze_js_bundle(BASE_URL)

        assert len(result) == 2
        succeeded = [f for f in result if f.content is not None]
        assert len(succeeded) == 1
        assert succeeded[0].content == "var fast = true;"

    def test_fetch_bundle_hits_timeout_hit_has_none_status_code(self):
        """Um BundleHit de timeout tem status_code=None e error_message não-vazio."""
        html_body = _html_with_scripts("/assets/slow.js")
        html_resp = _make_response(200, body=html_body)

        with patch(
            "toolkit.execution.checks.bundle.requests.get",
            side_effect=[html_resp, req_lib.exceptions.Timeout("timeout")],
        ):
            hits = fetch_bundle_hits(BASE_URL)

        assert len(hits) == 1
        hit = hits[0]
        assert hit.status_code is None
        assert hit.error_message is not None
        assert hit.content is None


# ---------------------------------------------------------------------------
# 5. Falha no fetch do HTML
# ---------------------------------------------------------------------------

class TestHtmlFetchFailure:
    """Quando a página HTML não pode ser obtida, retorna lista vazia."""

    def test_html_fetch_non_200_returns_empty_list(self):
        """HTML não-200 → nenhum asset JS descoberto → lista vazia."""
        html_resp = _make_response(404)

        with patch(
            "toolkit.execution.checks.bundle.requests.get",
            return_value=html_resp,
        ):
            result = analyze_js_bundle(BASE_URL)

        assert result == []

    def test_html_fetch_timeout_returns_empty_list(self):
        """Timeout no HTML → degradação graciosa → lista vazia."""
        with patch(
            "toolkit.execution.checks.bundle.requests.get",
            side_effect=req_lib.exceptions.Timeout("HTML timeout"),
        ):
            result = analyze_js_bundle(BASE_URL)

        assert result == []

    def test_html_fetch_connection_error_returns_empty_list(self):
        """Erro de conexão no HTML → degradação graciosa → lista vazia."""
        with patch(
            "toolkit.execution.checks.bundle.requests.get",
            side_effect=req_lib.exceptions.ConnectionError("refused"),
        ):
            result = analyze_js_bundle(BASE_URL)

        assert result == []

    def test_no_js_assets_in_html_returns_empty_list(self):
        """HTML sem tags <script src='.js'> → lista vazia."""
        html_resp = _make_response(200, body="<html><body>Hello</body></html>")

        with patch(
            "toolkit.execution.checks.bundle.requests.get",
            return_value=html_resp,
        ):
            result = analyze_js_bundle(BASE_URL)

        assert result == []


# ---------------------------------------------------------------------------
# 6. Integração com AuditLogger
# ---------------------------------------------------------------------------

class TestAuditLoggerIntegration:
    """Falhas são registradas no AuditLogger quando um é fornecido (parâmetro logger)."""

    def test_audit_logger_records_non_200_failure(self):
        """Uma falha de download não-200 é logada como AuditEvent."""
        html_body = _html_with_scripts("/assets/bad.js")
        html_resp = _make_response(200, body=html_body)
        bad_resp = _make_response(500)
        audit_logger = AuditLogger()

        with patch(
            "toolkit.execution.checks.bundle.requests.get",
            side_effect=[html_resp, bad_resp],
        ):
            analyze_js_bundle(BASE_URL, logger=audit_logger)

        events = audit_logger.get_events()
        assert len(events) == 1
        event = events[0]
        assert event.event_type == "error"
        assert event.module == "bundle"
        assert event.detail["status_code"] == 500

    def test_audit_logger_records_timeout_failure(self):
        """Uma falha de timeout é logada como AuditEvent."""
        html_body = _html_with_scripts("/assets/slow.js")
        html_resp = _make_response(200, body=html_body)
        audit_logger = AuditLogger()

        with patch(
            "toolkit.execution.checks.bundle.requests.get",
            side_effect=[html_resp, req_lib.exceptions.Timeout("timeout")],
        ):
            analyze_js_bundle(BASE_URL, logger=audit_logger)

        events = audit_logger.get_events()
        assert len(events) == 1
        event = events[0]
        assert event.event_type == "error"
        assert event.module == "bundle"
        assert event.detail["status_code"] is None

    def test_audit_logger_not_called_on_success(self):
        """Nenhum AuditEvent é logado quando todos os downloads são bem-sucedidos."""
        html_body = _html_with_scripts("/assets/app.js")
        html_resp = _make_response(200, body=html_body)
        js_resp = _make_response(200, body="var x = 1;")
        audit_logger = AuditLogger()

        with patch(
            "toolkit.execution.checks.bundle.requests.get",
            side_effect=[html_resp, js_resp],
        ):
            analyze_js_bundle(BASE_URL, logger=audit_logger)

        events = audit_logger.get_events()
        assert events == []

    def test_audit_logger_records_url_in_target(self):
        """A URL com falha aparece como target no AuditEvent."""
        html_body = _html_with_scripts("/assets/broken.js")
        html_resp = _make_response(200, body=html_body)
        bad_resp = _make_response(403)
        audit_logger = AuditLogger()

        with patch(
            "toolkit.execution.checks.bundle.requests.get",
            side_effect=[html_resp, bad_resp],
        ):
            analyze_js_bundle(BASE_URL, logger=audit_logger)

        events = audit_logger.get_events()
        assert len(events) == 1
        assert "broken.js" in events[0].target

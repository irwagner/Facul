"""
Reporter — Relatório técnico de auditoria de segurança (Req. 11).

Este módulo implementa o componente ``Reporter`` responsável por:
  - Ordenar achados por severidade decrescente e depois confiança decrescente (Req. 11.5)
  - Selecionar os top-k próximos passos prioritários por severidade + facilidade de correção (Req. 11.6)
  - Renderizar o relatório em Markdown e HTML auto-contido (Req. 11.4) — stubs para task 14.4
  - Gerar os artefatos .md e .html no diretório de saída (Req. 11.1) — stub para task 14.4
"""

from __future__ import annotations

import html as _html
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from toolkit.models import Finding, SessionState


# ---------------------------------------------------------------------------
# Ordem canônica de severidade e confiança (pública)
# ---------------------------------------------------------------------------

# Rank de severidade: menor rank = maior severidade (critical=0 é o mais grave)
SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}

# Rank de confiança: menor rank = maior confiança (high=0 é a mais confiante)
CONFIDENCE_ORDER: dict[str, int] = {
    "high": 0,
    "medium": 1,
    "low": 2,
}

# Aliases privados mantidos por compatibilidade interna (valores invertidos para
# uso com sorted(..., reverse=True) — mantém a semântica descendente dos helpers)
_SEVERITY_ORDER: dict[str, int] = {k: 3 - v for k, v in SEVERITY_ORDER.items()}
_CONFIDENCE_ORDER: dict[str, int] = {k: 2 - v for k, v in CONFIDENCE_ORDER.items()}


# ---------------------------------------------------------------------------
# Helpers de ordenação e pontuação
# ---------------------------------------------------------------------------


def _severity_key(finding: "Finding") -> int:
    """Retorna o valor numérico da severidade (quanto maior, mais severo)."""
    return _SEVERITY_ORDER.get(finding.severity, 0)


def _confidence_key(finding: "Finding") -> int:
    """Retorna o valor numérico da confiança (quanto maior, mais confiante)."""
    return _CONFIDENCE_ORDER.get(finding.confidence, 0)


def _ease_of_remediation_key(finding: "Finding") -> int:
    """
    Estima a facilidade de correção pelo comprimento do texto de remediação:
    textos mais curtos indicam instruções mais diretas e, portanto, correção mais fácil.

    Retorna um valor negativo do comprimento para que, ao ordenar de forma
    decrescente, achados com remediação mais curta apareçam primeiro.
    """
    return -len(finding.remediation)


def order_findings(findings: list["Finding"]) -> list["Finding"]:
    """
    Ordena os achados por severidade decrescente e, em empate, por confiança decrescente.

    A ordem de severidade é: critical > high > medium > low.
    A ordem de confiança é: high > medium > low.

    Requisito: 11.5
    Property 22: Relatório é uma permutação ordenada de todos os findings

    Parameters
    ----------
    findings:
        Lista de achados a ordenar.

    Returns
    -------
    list[Finding]
        Nova lista ordenada (a original não é modificada).
    """
    return sorted(
        findings,
        key=lambda f: (_severity_key(f), _confidence_key(f)),
        reverse=True,
    )


def top_next_steps(findings: list["Finding"], k: int = 3) -> list["Finding"]:
    """
    Retorna os ``k`` achados de maior prioridade para os próximos passos.

    A prioridade é calculada como uma combinação de severidade (peso principal)
    e facilidade de correção (peso secundário). A facilidade de correção é
    estimada inversamente ao comprimento do texto de ``remediation``:
    remediações mais curtas são consideradas mais fáceis de implementar.

    Se houver menos de ``k`` achados, retorna todos.

    Requisito: 11.6
    Property 23: Seleção dos próximos passos prioritários

    Parameters
    ----------
    findings:
        Lista de achados candidatos.
    k:
        Número máximo de próximos passos a retornar (padrão: 3).

    Returns
    -------
    list[Finding]
        Lista com no máximo ``k`` achados, ordenados por prioridade decrescente.
    """
    sorted_by_priority = sorted(
        findings,
        # Primeiro: severidade desc; segundo: facilidade de correção desc (= remediação mais curta)
        key=lambda f: (_severity_key(f), _ease_of_remediation_key(f)),
        reverse=True,
    )
    return sorted_by_priority[:k]


# ---------------------------------------------------------------------------
# Reporter class
# ---------------------------------------------------------------------------


@dataclass
class ReportArtifacts:
    """
    Artefatos gerados pelo ``Reporter.generate``.

    Attributes
    ----------
    markdown_path:
        Caminho do arquivo Markdown gerado.
    html_path:
        Caminho do arquivo HTML gerado.
    """

    markdown_path: str
    html_path: str


class Reporter:
    """
    Consolida os achados da sessão em relatório técnico (Req. 11).

    Métodos de ordenação e seleção de próximos passos estão implementados
    nesta task (14.1). Os métodos de renderização e geração de artefatos
    serão implementados na task 14.4.
    """

    # ------------------------------------------------------------------
    # Ordenação e seleção (task 14.1)
    # ------------------------------------------------------------------

    def order_findings(self, findings: list["Finding"]) -> list["Finding"]:
        """
        Ordena os achados por severidade decrescente e, em empate, por confiança
        decrescente.

        Delega para a função de módulo ``order_findings``.

        Requisito: 11.5
        """
        return order_findings(findings)

    def top_next_steps(
        self, findings: list["Finding"], k: int = 3
    ) -> list["Finding"]:
        """
        Retorna os top ``k`` achados por severidade e facilidade de correção.

        Delega para a função de módulo ``top_next_steps``.

        Requisito: 11.6
        """
        return top_next_steps(findings, k=k)

    # ------------------------------------------------------------------
    # Renderização e geração de artefatos (stubs — task 14.4)
    # ------------------------------------------------------------------

    def render_markdown(self, session: "SessionState") -> str:
        """
        Renderiza o relatório completo em formato Markdown.

        Seções: Capa, Sumário Executivo, Tabela de Achados, Detalhes de cada
        achado e Próximos Passos Recomendados.

        O detalhe de cada achado inclui todos os campos obrigatórios (Req. 11.3):
        id, título, severidade, confiança, descrição, endpoint afetado,
        evidência técnica, impacto, orientação de correção e referências.

        Quando a sessão não possui findings, é incluída uma nota indicando que
        nenhuma vulnerabilidade foi identificada (Req. 11.7).

        Requisito: 11.1, 11.2, 11.3, 11.4, 11.7
        """
        auth = session.authorization
        ordered = self.order_findings(list(session.findings))
        lines: list[str] = []

        # --- Capa (Cover Page) -------------------------------------------------
        lines.append("# Relatório Técnico de Auditoria de Segurança")
        lines.append("")
        lines.append("## Capa")
        lines.append("")
        lines.append(f"- **Domínio auditado:** {auth.domain}")
        lines.append(f"- **Instituição:** {auth.institution}")
        lines.append(f"- **Data da autorização:** {auth.auth_date.isoformat()}")
        lines.append(f"- **Diretório de trabalho:** {session.working_dir}")
        lines.append("")

        # --- Sumário Executivo (Executive Summary) ----------------------------
        lines.append("## Sumário Executivo")
        lines.append("")
        if ordered:
            counts = self._severity_counts(ordered)
            breakdown = ", ".join(
                f"{counts[sev]} {sev}" for sev in ("critical", "high", "medium", "low")
                if counts[sev] > 0
            )
            lines.append(
                f"Foram registrados {len(ordered)} achado(s) durante a sessão de "
                f"auditoria ({breakdown})."
            )
        else:
            lines.append(
                "Nenhuma vulnerabilidade foi identificada nos testes realizados."
            )
        lines.append("")

        # --- Tabela de Achados (Findings Table) -------------------------------
        lines.append("## Tabela de Achados")
        lines.append("")
        if ordered:
            lines.append("| ID | Título | Severidade | Confiança | Status |")
            lines.append("| --- | --- | --- | --- | --- |")
            for f in ordered:
                lines.append(
                    f"| {f.id} | {f.title} | {f.severity} | {f.confidence} | {f.status} |"
                )
        else:
            lines.append(
                "_Nenhuma vulnerabilidade foi identificada nos testes realizados._"
            )
        lines.append("")

        # --- Detalhes (Finding Details) ---------------------------------------
        lines.append("## Detalhes dos Achados")
        lines.append("")
        if ordered:
            for f in ordered:
                lines.extend(self._finding_detail_markdown(f))
        else:
            lines.append(
                "_Nenhuma vulnerabilidade foi identificada nos testes realizados._"
            )
            lines.append("")

        # --- Próximos Passos Recomendados (Recommended Next Steps) ------------
        lines.append("## Próximos Passos Recomendados")
        lines.append("")
        next_steps = self.top_next_steps(ordered)
        if next_steps:
            for i, f in enumerate(next_steps, start=1):
                lines.append(f"{i}. **{f.title}** ({f.severity}) — {f.remediation}")
        else:
            lines.append(
                "_Nenhuma vulnerabilidade foi identificada nos testes realizados._"
            )
        lines.append("")

        return "\n".join(lines)

    def render_html(self, session: "SessionState") -> str:
        """
        Renderiza o relatório completo em HTML auto-contido (CSS inline).

        Replica a estrutura do relatório Markdown (Capa, Sumário Executivo,
        Tabela de Achados, Detalhes e Próximos Passos Recomendados) com todos
        os campos obrigatórios de cada achado (Req. 11.3) e CSS embutido para
        facilitar o compartilhamento (Req. 11.4).

        Requisito: 11.1, 11.2, 11.3, 11.4, 11.7
        """
        auth = session.authorization
        ordered = self.order_findings(list(session.findings))

        def esc(value: object) -> str:
            return _html.escape(str(value))

        parts: list[str] = []
        parts.append("<!DOCTYPE html>")
        parts.append('<html lang="pt-BR">')
        parts.append("<head>")
        parts.append('<meta charset="utf-8">')
        parts.append(
            '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
        )
        parts.append("<title>Relatório Técnico de Auditoria de Segurança</title>")
        parts.append(self._inline_css())
        parts.append("</head>")
        parts.append("<body>")

        parts.append("<h1>Relatório Técnico de Auditoria de Segurança</h1>")

        # --- Capa --------------------------------------------------------------
        parts.append('<section class="cover">')
        parts.append("<h2>Capa</h2>")
        parts.append("<ul>")
        parts.append(f"<li><strong>Domínio auditado:</strong> {esc(auth.domain)}</li>")
        parts.append(f"<li><strong>Instituição:</strong> {esc(auth.institution)}</li>")
        parts.append(
            f"<li><strong>Data da autorização:</strong> {esc(auth.auth_date.isoformat())}</li>"
        )
        parts.append(
            f"<li><strong>Diretório de trabalho:</strong> {esc(session.working_dir)}</li>"
        )
        parts.append("</ul>")
        parts.append("</section>")

        # --- Sumário Executivo -------------------------------------------------
        parts.append('<section class="executive-summary">')
        parts.append("<h2>Sumário Executivo</h2>")
        if ordered:
            counts = self._severity_counts(ordered)
            breakdown = ", ".join(
                f"{counts[sev]} {sev}"
                for sev in ("critical", "high", "medium", "low")
                if counts[sev] > 0
            )
            parts.append(
                f"<p>Foram registrados {len(ordered)} achado(s) durante a sessão de "
                f"auditoria ({esc(breakdown)}).</p>"
            )
        else:
            parts.append(
                "<p>Nenhuma vulnerabilidade foi identificada nos testes realizados.</p>"
            )
        parts.append("</section>")

        # --- Tabela de Achados -------------------------------------------------
        parts.append('<section class="findings-table">')
        parts.append("<h2>Tabela de Achados</h2>")
        if ordered:
            parts.append("<table>")
            parts.append(
                "<thead><tr><th>ID</th><th>Título</th><th>Severidade</th>"
                "<th>Confiança</th><th>Status</th></tr></thead>"
            )
            parts.append("<tbody>")
            for f in ordered:
                parts.append(
                    "<tr>"
                    f"<td>{esc(f.id)}</td>"
                    f"<td>{esc(f.title)}</td>"
                    f'<td class="sev-{esc(f.severity)}">{esc(f.severity)}</td>'
                    f"<td>{esc(f.confidence)}</td>"
                    f"<td>{esc(f.status)}</td>"
                    "</tr>"
                )
            parts.append("</tbody>")
            parts.append("</table>")
        else:
            parts.append(
                "<p><em>Nenhuma vulnerabilidade foi identificada nos testes "
                "realizados.</em></p>"
            )
        parts.append("</section>")

        # --- Detalhes ----------------------------------------------------------
        parts.append('<section class="finding-details">')
        parts.append("<h2>Detalhes dos Achados</h2>")
        if ordered:
            for f in ordered:
                parts.append(self._finding_detail_html(f, esc))
        else:
            parts.append(
                "<p><em>Nenhuma vulnerabilidade foi identificada nos testes "
                "realizados.</em></p>"
            )
        parts.append("</section>")

        # --- Próximos Passos Recomendados -------------------------------------
        parts.append('<section class="next-steps">')
        parts.append("<h2>Próximos Passos Recomendados</h2>")
        next_steps = self.top_next_steps(ordered)
        if next_steps:
            parts.append("<ol>")
            for f in next_steps:
                parts.append(
                    f"<li><strong>{esc(f.title)}</strong> ({esc(f.severity)}) — "
                    f"{esc(f.remediation)}</li>"
                )
            parts.append("</ol>")
        else:
            parts.append(
                "<p><em>Nenhuma vulnerabilidade foi identificada nos testes "
                "realizados.</em></p>"
            )
        parts.append("</section>")

        parts.append("</body>")
        parts.append("</html>")

        return "\n".join(parts)

    def generate(
        self, session: "SessionState", out_dir: str
    ) -> "ReportArtifacts":
        """
        Gera os arquivos ``.md`` e ``.html`` no diretório ``out_dir``.

        Trata a sessão sem findings com uma nota indicando que nenhuma
        vulnerabilidade foi identificada (Req. 11.7).

        Requisito: 11.1, 11.7
        """
        os.makedirs(out_dir, exist_ok=True)

        markdown_content = self.render_markdown(session)
        html_content = self.render_html(session)

        markdown_path = os.path.join(out_dir, "report.md")
        html_path = os.path.join(out_dir, "report.html")

        with open(markdown_path, "w", encoding="utf-8") as fh:
            fh.write(markdown_content)
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(html_content)

        return ReportArtifacts(markdown_path=markdown_path, html_path=html_path)

    # ------------------------------------------------------------------
    # Internal rendering helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _severity_counts(findings: list["Finding"]) -> dict[str, int]:
        """Count findings per severity level."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    @staticmethod
    def _finding_detail_markdown(f: "Finding") -> list[str]:
        """Render a single finding's mandatory fields as Markdown lines (Req. 11.3)."""
        endpoint = f.affected_endpoint if f.affected_endpoint else "N/A"
        references = ", ".join(f.references) if f.references else "N/A"
        lines = [
            f"### {f.id}: {f.title}",
            "",
            f"- **ID:** {f.id}",
            f"- **Título:** {f.title}",
            f"- **Severidade:** {f.severity}",
            f"- **Confiança:** {f.confidence}",
            f"- **Status:** {f.status}",
            f"- **Descrição:** {f.summary}",
            f"- **Endpoint afetado:** {endpoint}",
            f"- **Evidência técnica:** {f.evidence}",
            f"- **Impacto:** {f.impact}",
            f"- **Orientação de correção:** {f.remediation}",
            f"- **Referências:** {references}",
            "",
        ]
        return lines

    @staticmethod
    def _finding_detail_html(f: "Finding", esc) -> str:
        """Render a single finding's mandatory fields as an HTML block (Req. 11.3)."""
        endpoint = esc(f.affected_endpoint) if f.affected_endpoint else "N/A"
        references = esc(", ".join(f.references)) if f.references else "N/A"
        return (
            f'<article class="finding sev-{esc(f.severity)}">'
            f"<h3>{esc(f.id)}: {esc(f.title)}</h3>"
            "<ul>"
            f"<li><strong>ID:</strong> {esc(f.id)}</li>"
            f"<li><strong>Título:</strong> {esc(f.title)}</li>"
            f"<li><strong>Severidade:</strong> {esc(f.severity)}</li>"
            f"<li><strong>Confiança:</strong> {esc(f.confidence)}</li>"
            f"<li><strong>Status:</strong> {esc(f.status)}</li>"
            f"<li><strong>Descrição:</strong> {esc(f.summary)}</li>"
            f"<li><strong>Endpoint afetado:</strong> {endpoint}</li>"
            f"<li><strong>Evidência técnica:</strong> {esc(f.evidence)}</li>"
            f"<li><strong>Impacto:</strong> {esc(f.impact)}</li>"
            f"<li><strong>Orientação de correção:</strong> {esc(f.remediation)}</li>"
            f"<li><strong>Referências:</strong> {references}</li>"
            "</ul>"
            "</article>"
        )

    @staticmethod
    def _inline_css() -> str:
        """Return a ``<style>`` block with inline CSS for a self-contained HTML (Req. 11.4)."""
        return (
            "<style>"
            "body{font-family:Arial,Helvetica,sans-serif;margin:2rem;color:#1a1a1a;"
            "line-height:1.5;}"
            "h1{border-bottom:3px solid #2c3e50;padding-bottom:.5rem;}"
            "h2{margin-top:2rem;color:#2c3e50;border-bottom:1px solid #ddd;}"
            "table{border-collapse:collapse;width:100%;margin:1rem 0;}"
            "th,td{border:1px solid #ccc;padding:.5rem;text-align:left;}"
            "th{background:#2c3e50;color:#fff;}"
            ".finding{border:1px solid #ddd;border-radius:6px;padding:1rem;margin:1rem 0;}"
            ".sev-critical{border-left:6px solid #c0392b;}"
            ".sev-high{border-left:6px solid #e67e22;}"
            ".sev-medium{border-left:6px solid #f1c40f;}"
            ".sev-low{border-left:6px solid #27ae60;}"
            "</style>"
        )

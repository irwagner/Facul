"""
NucleiAdapter — integração com a ferramenta externa Nuclei via subprocess.

Implementa disponibilidade (is_available / get_install_instructions),
execução (run), parsing JSONL (parse_output), re-serialização (serialize)
e deduplicação (deduplicate) do Nuclei conforme os Requisitos 10.1–10.6.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field

from toolkit.exceptions import NucleiError
from toolkit.models import NucleiFinding


@dataclass
class NucleiRun:
    """Resultado de uma execução do Nuclei via subprocess."""

    stdout: str
    stderr: str
    exit_code: int
    output_file: str | None  # caminho para o arquivo de saída JSON


class NucleiAdapter:
    """
    Adaptador para o binário Nuclei.

    Permite verificar disponibilidade do binário, obter instruções de
    instalação por SO e executar o Nuclei contra um alvo com tags
    específicas, capturando stdout/stderr/exit_code (Req. 10.1, 10.2, 10.6).
    """

    def is_available(self) -> bool:
        """
        Verifica se o binário ``nuclei`` está disponível no PATH.

        Returns:
            ``True`` se o binário for encontrado, ``False`` caso contrário
            (Req. 10.1).
        """
        return shutil.which("nuclei") is not None

    def get_install_instructions(self) -> str:
        """
        Retorna instruções de instalação do Nuclei adequadas ao SO atual.

        Detecta a plataforma via ``sys.platform`` e retorna as instruções
        correspondentes para Linux, macOS ou Windows (Req. 10.1).

        Returns:
            String com os comandos/passos de instalação para a plataforma.
        """
        platform = sys.platform

        if platform == "darwin":
            return (
                "Install via: brew install nuclei\n"
                "Or: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            )
        elif platform.startswith("win"):
            return (
                "Install via: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n"
                "Or download from: https://github.com/projectdiscovery/nuclei/releases"
            )
        else:
            # linux and other POSIX platforms
            return (
                "Install via: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n"
                "Or: apt-get install nuclei (if available)"
            )

    def run(self, target: str, tags: list[str]) -> NucleiRun:
        """
        Executa o Nuclei contra o alvo fornecido com as tags especificadas.

        Cria um arquivo temporário para a saída JSON, monta o comando
        apropriado e invoca o Nuclei via ``subprocess.run``. Captura
        stdout, stderr e o código de saída (Req. 10.2, 10.6).

        Args:
            target: URL ou host alvo da varredura.
            tags:   Lista de tags para filtrar templates Nuclei. Se vazia,
                    o argumento ``-t`` é omitido (todos os templates são
                    executados).

        Returns:
            :class:`NucleiRun` com stdout, stderr, exit_code e o caminho
            para o arquivo de saída JSON.

        Raises:
            NucleiError: Quando o processo Nuclei encerra com exit_code
                         diferente de zero (Req. 10.6).
        """
        output_file: str = tempfile.mktemp(suffix=".json")

        # Montar o comando base
        cmd: list[str] = ["nuclei", "-u", target]

        # Adicionar filtro de tags apenas se não estiver vazia
        if tags:
            cmd += ["-t", ",".join(tags)]

        # Saída JSONL e modo silencioso
        cmd += ["-je", output_file, "-silent"]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            raise NucleiError(
                f"Nuclei failed with exit code {result.returncode}",
                stderr=result.stderr,
                exit_code=result.returncode,
            )

        return NucleiRun(
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.returncode,
            output_file=output_file,
        )

    def parse_output(self, jsonl_text: str) -> list[NucleiFinding]:
        """
        Faz o parsing de saída JSONL do Nuclei, linha a linha.

        Campos não modelados são preservados em ``extra`` para garantir
        o round-trip de serialização (Req. 10.3, 10.5).

        Args:
            jsonl_text: Conteúdo do arquivo de saída do Nuclei (uma linha
                        JSON por finding).

        Returns:
            Lista de :class:`NucleiFinding` extraídos da saída.
        """
        findings: list[NucleiFinding] = []
        for line in jsonl_text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                findings.append(NucleiFinding.from_dict(record))
            except (json.JSONDecodeError, KeyError):
                # Linha malformada — pular silenciosamente
                continue
        return findings

    def serialize(self, findings: list[NucleiFinding]) -> str:
        """
        Re-serializa uma lista de :class:`NucleiFinding` para o formato JSONL.

        Cada finding é convertido para um dicionário via ``to_dict`` e
        serializado como uma linha JSON (Req. 10.5).

        Args:
            findings: Lista de findings a serializar.

        Returns:
            String JSONL (uma linha por finding, sem trailing newline).
        """
        lines: list[str] = [json.dumps(f.to_dict(), ensure_ascii=False) for f in findings]
        return "\n".join(lines)

    def deduplicate(self, findings: list[NucleiFinding]) -> list[NucleiFinding]:
        """
        Remove findings duplicados pela chave composta ``(template_id, host)``.

        Mantém apenas a primeira ocorrência de cada chave, preservando a
        ordem relativa dos elementos restantes (Req. 10.4).

        Args:
            findings: Lista de findings possivelmente contendo duplicatas.

        Returns:
            Nova lista sem duplicatas, com a ordem dos primeiros elementos
            preservada.
        """
        seen: set[tuple[str, str]] = set()
        result: list[NucleiFinding] = []
        for finding in findings:
            key = (finding.template_id, finding.host)
            if key not in seen:
                seen.add(key)
                result.append(finding)
        return result

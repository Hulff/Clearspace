"""Local, rule-based assistant for scan summaries; no GTK or network access."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import unicodedata

from .contracts import (
    Assistant,
    AssistantReply,
    ProposedAction,
    ProposedActionKind,
    Risk,
)
from .core import format_bytes


@dataclass(frozen=True, slots=True)
class ScanConsumer:
    """A measured item and its already evaluated risk for assistant context."""

    path: Path
    name: str
    size_bytes: int
    risk: Risk
    summary: str = ""

    def __post_init__(self) -> None:
        if self.size_bytes < 0:
            raise ValueError("size_bytes cannot be negative")


@dataclass(frozen=True, slots=True)
class AssistantScanContext:
    """Small scan summary; callers pass only the largest few consumers."""

    dirs_scanned: int
    duration_ms: int
    free_bytes: int
    total_bytes: int
    biggest_consumers: tuple[ScanConsumer, ...] = ()
    selected_consumer: ScanConsumer | None = None

    def __post_init__(self) -> None:
        for field_name in ("dirs_scanned", "duration_ms", "free_bytes", "total_bytes"):
            if getattr(self, field_name) < 0:
                raise ValueError(f"{field_name} cannot be negative")


class LocalRuleAssistant(Assistant):
    """Answer common disk usage questions from the current scan context.

    Proposals can only highlight a node or open the review flow. The UI maps
    them to navigation/review dialogs, never to checkbox changes or execution.
    """

    fallback = (
        "Ainda não sei responder isso com os dados da varredura. Posso mostrar "
        "os maiores itens ou explicar o risco de um item selecionado."
    )

    def respond(self, message: str, context: object) -> AssistantReply:
        if not isinstance(context, AssistantScanContext):
            return AssistantReply(self.fallback)
        question = _normalize(message)
        if any(term in question for term in (
            "maior", "maiores", "mais espaco", "usando mais", "most space", "largest", "biggest"
        )):
            return self._largest_items(context)
        if any(term in question for term in ("segura", "safe cleanup", "limpeza segura", "limpar com segurança")):
            return self._safe_cleanup(context)
        if any(term in question for term in ("risco", "risk", "perigoso", "danger")):
            return self._explain_selected(context)
        if any(term in question for term in ("resumo", "summary", "scan", "varredura", "espaço livre")):
            return AssistantReply(self.greeting(context))
        return AssistantReply(self.fallback)

    @staticmethod
    def greeting(context: AssistantScanContext) -> str:
        mins, secs = divmod(context.duration_ms // 1000, 60)
        lines = [
            f"A varredura analisou {context.dirs_scanned:,} pastas em {mins}:{secs:02d}.",
            f"Há {format_bytes(context.free_bytes)} livres de {format_bytes(context.total_bytes)}.",
        ]
        if context.biggest_consumers:
            lines.append("Maiores consumidores:")
            lines.extend(
                f"• {item.name}: {format_bytes(item.size_bytes)}"
                for item in context.biggest_consumers[:2]
            )
        else:
            lines.append("Ainda não há consumidores disponíveis no resumo da varredura.")
        return "\n".join(lines)

    @staticmethod
    def _largest_items(context: AssistantScanContext) -> AssistantReply:
        if not context.biggest_consumers:
            return AssistantReply("Ainda não há itens medidos para comparar.")
        lines = ["Maiores consumidores encontrados:"]
        lines.extend(
            f"{index}. {item.name} — {format_bytes(item.size_bytes)} "
            f"(risco: {_risk_label(item.risk)})"
            for index, item in enumerate(context.biggest_consumers[:4], 1)
        )
        proposal = ProposedAction(
            ProposedActionKind.HIGHLIGHT_NODE,
            str(context.biggest_consumers[0].path),
        )
        return AssistantReply("\n".join(lines), (proposal,))

    @staticmethod
    def _safe_cleanup(context: AssistantScanContext) -> AssistantReply:
        safe_item = next(
            (item for item in context.biggest_consumers if item.risk is Risk.LOW), None
        )
        if safe_item is None:
            return AssistantReply(
                "Não encontrei um item classificado como baixo risco entre os maiores. "
                "Revise os avisos na árvore; nenhum item foi selecionado."
            )
        proposal = ProposedAction(
            ProposedActionKind.HIGHLIGHT_NODE,
            str(safe_item.path),
        )
        extra = f" {safe_item.summary}" if safe_item.summary else ""
        return AssistantReply(
            f"Uma opção de baixo risco para revisar é {safe_item.name} "
            f"({format_bytes(safe_item.size_bytes)}).{extra} "
            "Confira a revisão antes de qualquer ação; não selecionei nem removi nada.",
            (proposal,),
        )

    @staticmethod
    def _explain_selected(context: AssistantScanContext) -> AssistantReply:
        item = context.selected_consumer
        if item is None:
            return AssistantReply("Selecione um item na árvore para eu explicar o risco.")
        explanation = item.summary or _risk_explanation(item.risk)
        proposal = ProposedAction(ProposedActionKind.HIGHLIGHT_NODE, str(item.path))
        return AssistantReply(
            f"{item.name}: risco {_risk_label(item.risk)}. {explanation}", (proposal,)
        )


def _normalize(message: str) -> str:
    folded = unicodedata.normalize("NFKD", message.casefold())
    plain = "".join(character for character in folded if not unicodedata.combining(character))
    return re.sub(r"\s+", " ", plain).strip()


def _risk_label(risk: Risk) -> str:
    return {
        Risk.LOW: "baixo",
        Risk.MODERATE: "moderado",
        Risk.USER_DATA: "dados do usuário",
        Risk.CRITICAL: "crítico",
    }[risk]


def _risk_explanation(risk: Risk) -> str:
    return {
        Risk.LOW: "Geralmente pode ser recriado, mas revise o procedimento recomendado.",
        Risk.MODERATE: "Pode ter impacto local; leia o aviso e confirme o conteúdo.",
        Risk.USER_DATA: "Pode conter dados pessoais e exige confirmação reforçada.",
        Risk.CRITICAL: "É protegido e não pode ser removido pelo Clearspace.",
    }[risk]

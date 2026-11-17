from __future__ import annotations

from pathlib import Path

from clearspace.assistant import AssistantScanContext, LocalRuleAssistant, ScanConsumer
from clearspace.contracts import ProposedActionKind, Risk


def make_context(tmp_path: Path) -> AssistantScanContext:
    return AssistantScanContext(
        dirs_scanned=1280,
        duration_ms=65_000,
        free_bytes=2 * 1024**3,
        total_bytes=8 * 1024**3,
        biggest_consumers=(
            ScanConsumer(tmp_path / "cache", "cache", 3 * 1024**3, Risk.LOW,
                         "Pode ser recriado pela aplicação."),
            ScanConsumer(tmp_path / "projects", "projects", 2 * 1024**3, Risk.USER_DATA),
            ScanConsumer(tmp_path / "build", "build", 1024**3, Risk.MODERATE),
        ),
    )


def test_greeting_uses_real_synthetic_scan_summary(tmp_path: Path) -> None:
    assistant = LocalRuleAssistant()

    greeting = assistant.greeting(make_context(tmp_path))

    assert "1,280 pastas em 1:05" in greeting
    assert "2.0 GiB livres de 8.0 GiB" in greeting
    assert "cache: 3.0 GiB" in greeting
    assert "projects: 2.0 GiB" in greeting


def test_largest_question_lists_measured_items_and_only_proposes_highlight(
    tmp_path: Path,
) -> None:
    reply = LocalRuleAssistant().respond("O que está usando mais espaço?", make_context(tmp_path))

    assert "cache" in reply.text and "projects" in reply.text
    assert len(reply.proposed_actions) == 1
    action = reply.proposed_actions[0]
    assert action.kind is ProposedActionKind.HIGHLIGHT_NODE
    assert action.target == str(tmp_path / "cache")


def test_safe_cleanup_never_selects_or_executes_anything(tmp_path: Path) -> None:
    reply = LocalRuleAssistant().respond("Suggest a safe cleanup", make_context(tmp_path))

    assert "baixo risco" in reply.text
    assert "não selecionei nem removi nada" in reply.text
    assert all(action.kind is ProposedActionKind.HIGHLIGHT_NODE
               for action in reply.proposed_actions)
    assert not hasattr(ProposedActionKind, "DELETE")
    assert not hasattr(ProposedActionKind, "EXECUTE")


def test_risk_explanation_uses_selected_item_and_proposes_no_deletion(
    tmp_path: Path,
) -> None:
    context = make_context(tmp_path)
    selected = ScanConsumer(
        tmp_path / "credentials", "credentials", 1024, Risk.CRITICAL
    )
    context = AssistantScanContext(
        context.dirs_scanned,
        context.duration_ms,
        context.free_bytes,
        context.total_bytes,
        context.biggest_consumers,
        selected,
    )

    reply = LocalRuleAssistant().respond("Explique o risco", context)

    assert "crítico" in reply.text
    assert "não pode ser removido" in reply.text
    assert [action.kind for action in reply.proposed_actions] == [
        ProposedActionKind.HIGHLIGHT_NODE
    ]
    assert reply.proposed_actions[0].target == str(selected.path)


def test_unknown_questions_have_friendly_answer_and_no_proposals() -> None:
    reply = LocalRuleAssistant().respond("Qual a previsão do tempo?", object())

    assert "Ainda não sei responder" in reply.text
    assert reply.proposed_actions == ()

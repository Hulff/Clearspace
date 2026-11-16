"""Generic risk rules and native procedure recommendations."""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .contracts import MatcherKind, Node, Procedure, Risk, Rule, RuleMatcher

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RuleEvaluation:
    category: str
    risk: Risk
    warnings: tuple[str, ...]
    recommended_procedure: Procedure | None = None
    git_has_uncommitted_changes: bool | None = None


RULES: tuple[Rule, ...] = (
    Rule(RuleMatcher(MatcherKind.CATEGORY, "regenerable_cache"), Risk.LOW,
         "Cache regenerável; a aplicação pode precisar reconstruí-lo."),
    Rule(RuleMatcher(MatcherKind.NAME, "go-build"), Risk.LOW,
         "Use o comando nativo do Go para limpar este cache.", "go-build-cache"),
    Rule(RuleMatcher(MatcherKind.NAME, "node_modules"), Risk.MODERATE,
         "Dependências do projeto; podem ser reinstaladas pelo gerenciador."),
    Rule(RuleMatcher(MatcherKind.NAME, "target"), Risk.LOW,
         "Saída de build Rust; pode ser recriada com Cargo.", "cargo-build-cache"),
    Rule(RuleMatcher(MatcherKind.NAME, "build"), Risk.MODERATE,
         "Diretório de build; confirme que não contém arquivos próprios."),
    Rule(RuleMatcher(MatcherKind.CATEGORY, "trash"), Risk.USER_DATA,
         "A lixeira pode conter arquivos que ainda deseja recuperar."),
    Rule(RuleMatcher(MatcherKind.CATEGORY, "browser_profile"), Risk.USER_DATA,
         "Perfis de navegador contêm sessões, histórico e dados pessoais."),
    Rule(RuleMatcher(MatcherKind.CATEGORY, "container_volume"), Risk.USER_DATA,
         "Volumes podem conter bancos de dados e outros dados persistentes."),
    Rule(RuleMatcher(MatcherKind.CATEGORY, "model_or_dataset"), Risk.USER_DATA,
         "Modelos e datasets podem ser grandes ou caros para baixar novamente."),
    Rule(RuleMatcher(MatcherKind.CATEGORY, "git_repository"), Risk.USER_DATA,
         "Repositório pode conter trabalho local e alterações não commitadas."),
    Rule(RuleMatcher(MatcherKind.CATEGORY, "game_data"), Risk.USER_DATA,
         "Dados de jogos podem incluir mundos, configurações e saves."),
    Rule(RuleMatcher(MatcherKind.CATEGORY, "credentials"), Risk.CRITICAL,
         "Chaves e credenciais são dados sensíveis e protegidos."),
    Rule(RuleMatcher(MatcherKind.CATEGORY, "system_journal"), Risk.MODERATE,
         "Prefira reduzir o journal com a ferramenta do sistema.", "journal-trim"),
    Rule(RuleMatcher(MatcherKind.CATEGORY, "package_cache"), Risk.MODERATE,
         "Prefira remover versões antigas com a ferramenta de cache do pacman.",
         "pacman-cache"),
    Rule(RuleMatcher(MatcherKind.NAME, "npm"), Risk.LOW,
         "Use a verificação nativa do npm antes de considerar qualquer remoção.",
         "npm-cache-verify"),
)


PROCEDURES: tuple[Procedure, ...] = (
    Procedure("go-build-cache", "Limpar cache de build do Go", ["go", "clean", "-cache"],
              False, "Remove o cache compilado; o Go o recria quando necessário.", True,
              executable="go"),
    Procedure("cargo-build-cache", "Limpar artefatos do projeto Cargo",
              ["cargo", "clean", "--manifest-path", "{path}/Cargo.toml"], False,
              "Remove artefatos de build do projeto atual.", True, executable="cargo"),
    Procedure("npm-cache-verify", "Verificar cache do npm", ["npm", "cache", "verify"],
              False, "Verifica a integridade do cache; não é uma limpeza de arquivos.", True,
              executable="npm"),
    Procedure("pacman-cache", "Remover versões antigas do cache do pacman",
              ["paccache", "-r"], True,
              "Remove pacotes antigos do cache do sistema.", True, executable="paccache"),
    Procedure("journal-trim", "Reduzir o journal do sistema",
              ["journalctl", "--vacuum-size=200M"], True,
              "Remove entradas antigas do journal até o limite informado.", False,
              executable="journalctl"),
)


class RuleEngine:
    """Classify nodes, return risk guidance, and expose installed procedures."""

    def __init__(self, *, rules: tuple[Rule, ...] = RULES,
                 procedures: tuple[Procedure, ...] = PROCEDURES,
                 command_runner=subprocess.run):
        self.rules = rules
        self.procedures = procedures
        self.command_runner = command_runner

    def available_procedures(self) -> tuple[Procedure, ...]:
        return tuple(procedure for procedure in self.procedures if procedure.available)

    def evaluate(self, node: Node, category: str | None = None) -> RuleEvaluation:
        inferred_category = category or self.classify(node)
        matched = [rule for rule in self.rules if rule.matcher.matches(
            name=node.name, category=inferred_category, path=node.path
        )]
        risk = max((rule.risk for rule in matched), key=_risk_rank, default=Risk.MODERATE)
        warnings = [rule.message for rule in matched]
        procedure = self._recommended_procedure(matched)
        git_state: bool | None = None

        if inferred_category == "git_repository":
            git_state, git_warning = self._git_status(node.path)
            if git_warning:
                warnings.append(git_warning)
            elif git_state:
                warnings.append("Há alterações não commitadas neste repositório.")
            else:
                warnings.append("Não foram encontradas alterações não commitadas.")

        if node.error:
            warnings.append(node.error)
        return RuleEvaluation(inferred_category, risk, tuple(warnings), procedure, git_state)

    @staticmethod
    def classify(node: Node) -> str:
        """Infer broad categories from generic path components and node names."""
        components = {part.casefold() for part in node.path.parts}
        name = node.name.casefold()
        if name in {".ssh", "credentials", "secrets", "private", "keys"} or any(
            part in {".ssh", "credentials", "secrets", "private", "keys"}
            for part in components
        ):
            return "credentials"
        if name in {".trash", "trash"} or "trash" in components:
            return "trash"
        if components & {".mozilla", "firefox", "chromium", "google-chrome", "browser"}:
            return "browser_profile"
        if components & {"volumes", "_data", "docker-volumes"}:
            return "container_volume"
        if components & {"huggingface", "models", "datasets", "model", "dataset"}:
            return "model_or_dataset"
        if node.is_dir and (node.path / ".git").exists():
            return "git_repository"
        if components & {"prismlauncher", ".minecraft", "saves", "worlds", "steam"}:
            return "game_data"
        if components & {".cache", "cache", "caches", "go-build", "pip", "npm", "yay"}:
            return "regenerable_cache"
        if components & {"journal", "journald", "systemd"}:
            return "system_journal"
        if components & {"pacman", "pkg", "package-cache"}:
            return "package_cache"
        return "filesystem"

    def _recommended_procedure(self, matched: list[Rule]) -> Procedure | None:
        ids = [rule.recommended_procedure_id for rule in matched
               if rule.recommended_procedure_id]
        if not ids:
            return None
        procedures = {procedure.id: procedure for procedure in self.available_procedures()}
        return next((procedures[procedure_id] for procedure_id in ids
                     if procedure_id in procedures), None)

    def _git_status(self, path: Path) -> tuple[bool | None, str | None]:
        if shutil.which("git") is None:
            return None, "Git não está instalado; não foi possível verificar alterações locais."
        try:
            result = self.command_runner(
                ["git", "-C", str(path), "status", "--porcelain"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            logger.warning("Could not inspect git status for %s: %s", path, error)
            return None, f"Não foi possível verificar o estado do Git: {error}"
        if result.returncode:
            detail = result.stderr.strip() or f"git status saiu com código {result.returncode}"
            logger.warning("Git status failed for %s: %s", path, detail)
            return None, f"Não foi possível verificar o estado do Git: {detail}"
        return bool(result.stdout.strip()), None


def _risk_rank(risk: Risk) -> int:
    return {
        Risk.LOW: 0,
        Risk.MODERATE: 1,
        Risk.USER_DATA: 2,
        Risk.CRITICAL: 3,
    }[risk]

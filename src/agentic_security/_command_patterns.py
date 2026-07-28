"""Internal bounded-regex validation for native agent command policies.

Command patterns are administrator-controlled configuration, but they still
cross a runtime availability boundary: Python's backtracking regex engine can
turn a pathological pattern into a hook timeout, and both Claude Code and
Codex may then continue without the intended decision. Every policy ingress
and matcher therefore uses this module instead of compiling arbitrary regex.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Sequence
from re import Pattern
from re import _constants as sre_constants  # type: ignore[attr-defined]
from re import _parser as sre_parser  # type: ignore[attr-defined]
from typing import Any, Final, cast

MAX_COMMAND_PATTERN_COUNT: Final = 100
MAX_COMMAND_PATTERN_LENGTH: Final = 256
MAX_COMMAND_TEXT_LENGTH: Final = 8_192

_BACKREFERENCE = re.compile(r"\\[1-9]")
_NAMED_UNICODE_ESCAPE = re.compile(r"\\N\{")
_QUANTIFIED_GROUP = re.compile(r"(?<!\\)\)(?:[+*?]|\{\d*(?:,\d*)?\})")
_REPEAT_OPS = frozenset(
    {
        sre_constants.MAX_REPEAT,
        sre_constants.MIN_REPEAT,
        sre_constants.POSSESSIVE_REPEAT,
    }
)
_SAFE_REPEAT_ATOMS = frozenset(
    {
        sre_constants.LITERAL,
        sre_constants.NOT_LITERAL,
        sre_constants.IN,
        sre_constants.CATEGORY,
    }
)
_SHELL_PUNCTUATION = "();<>|&"


def _category_matches_literal(category: object, literal: int) -> bool:
    """Return whether a supported regex category can consume one code point."""
    character = chr(literal)
    positive = {
        sre_constants.CATEGORY_DIGIT: character.isdigit(),
        sre_constants.CATEGORY_SPACE: character.isspace(),
        sre_constants.CATEGORY_WORD: character.isalnum() or character == "_",
        sre_constants.CATEGORY_LINEBREAK: character in "\r\n",
    }
    negative = {
        sre_constants.CATEGORY_NOT_DIGIT: sre_constants.CATEGORY_DIGIT,
        sre_constants.CATEGORY_NOT_SPACE: sre_constants.CATEGORY_SPACE,
        sre_constants.CATEGORY_NOT_WORD: sre_constants.CATEGORY_WORD,
        sre_constants.CATEGORY_NOT_LINEBREAK: sre_constants.CATEGORY_LINEBREAK,
    }
    if category in positive:
        return positive[category]
    if category in negative:
        return not positive[negative[category]]
    return True


def _atom_matches_literal(operation: object, argument: object, literal: int) -> bool:
    """Conservatively decide whether one supported atom can consume a literal."""
    if operation is sre_constants.LITERAL:
        return argument == literal
    if operation is sre_constants.NOT_LITERAL:
        return argument != literal
    if operation is sre_constants.CATEGORY:
        return _category_matches_literal(argument, literal)
    if operation is sre_constants.IN:
        entries = list(cast(Sequence[tuple[object, Any]], argument))
        negated = bool(entries and entries[0][0] is sre_constants.NEGATE)
        matched = any(
            (item_operation is sre_constants.LITERAL and item_argument == literal)
            or (
                item_operation is sre_constants.RANGE
                and item_argument[0] <= literal <= item_argument[1]
            )
            or (
                item_operation is sre_constants.CATEGORY
                and _category_matches_literal(item_argument, literal)
            )
            for item_operation, item_argument in entries
            if item_operation is not sre_constants.NEGATE
        )
        return not matched if negated else matched
    return True


def _atoms_may_overlap(left: tuple[object, object], right: tuple[object, object]) -> bool:
    """Return false only when two supported atoms are provably disjoint."""
    left_operation, left_argument = left
    right_operation, right_argument = right
    if right_operation is sre_constants.LITERAL:
        return _atom_matches_literal(left_operation, left_argument, right_argument)  # type: ignore[arg-type]
    if left_operation is sre_constants.LITERAL:
        return _atom_matches_literal(right_operation, right_argument, left_argument)  # type: ignore[arg-type]
    # Non-literal set intersection is intentionally conservative. Rejecting a
    # pattern that cannot be proven safe is preferable to a hook-timeout bypass.
    return True


def _leading_atoms(subpattern: Any) -> tuple[list[tuple[object, object]], bool]:
    """Return possible first consuming atoms and whether the expression is nullable."""
    atoms: list[tuple[object, object]] = []
    for operation, argument in subpattern.data:
        if operation is sre_constants.AT:
            continue
        if operation in _SAFE_REPEAT_ATOMS:
            return [(operation, argument)], False
        if operation is sre_constants.SUBPATTERN:
            _group, _add_flags, _delete_flags, nested = argument
            nested_atoms, nullable = _leading_atoms(nested)
            atoms.extend(nested_atoms)
            if not nullable:
                return atoms, False
            continue
        if operation is sre_constants.BRANCH:
            _none, branches = argument
            branch_results = [_leading_atoms(branch) for branch in branches]
            for branch_atoms, _nullable in branch_results:
                atoms.extend(branch_atoms)
            return atoms, any(nullable for _branch_atoms, nullable in branch_results)
        if operation in _REPEAT_OPS:
            minimum, _maximum, repeated = argument
            repeated_atoms, repeated_nullable = _leading_atoms(repeated)
            atoms.extend(repeated_atoms)
            if minimum > 0 and not repeated_nullable:
                return atoms, False
            continue
        # Unknown syntax cannot establish a safe separator.
        return [], True
    return atoms, True


def _subpattern_starts_disjoint(active_repeat_atom: tuple[object, object], subpattern: Any) -> bool:
    """Return true only when every possible first atom separates a prior repeat."""
    atoms, nullable = _leading_atoms(subpattern)
    return (
        bool(atoms)
        and not nullable
        and all(not _atoms_may_overlap(active_repeat_atom, atom) for atom in atoms)
    )


def command_is_single_invocation(command: str) -> bool:
    """Return whether Bash text contains one command without shell control flow.

    Complete regex matching is not enough because an administrator can include
    shell separators in an allow pattern. Newlines, substitutions, pipelines,
    redirections, lists and subshell syntax are always routed away from the
    native allow path. The check is deliberately conservative: quoted control
    syntax may also require the governed MCP path.
    """
    # Parameter expansion can replace the executable itself (for example
    # ``$SHELL -c id``) after policy evaluation and introduce a hidden parser.
    # Reject every dollar form conservatively rather than trying to recreate
    # shell environment, quoting and expansion semantics inside the SDK.
    if any(character in command for character in ("\0", "\r", "\n", "`", "$")):
        return False
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=_SHELL_PUNCTUATION)
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return False
    if not tokens:
        return False
    # Native allow rules authorize only the visible argv. Shell command-string
    # entry points create a second, hidden parsing boundary (for example
    # ``sh -c id`` or ``eval "$PAYLOAD"``) whose eventual operation is not the
    # text matched by the administrator's regex. Route every such invocation
    # through the governed execution path, including wrappers such as
    # ``env /bin/bash -c ...``. This is intentionally conservative.
    indirect_entry_points = frozenset(
        {".", "bash", "dash", "eval", "fish", "ksh", "sh", "source", "zsh"}
    )

    def executable_name(fragment: str) -> str:
        """Normalize host spelling before comparing parser entry points."""
        name = re.split(r"[/\\]", fragment)[-1].casefold()
        for suffix in (".exe", ".com", ".cmd", ".bat"):
            if name.endswith(suffix):
                return name[: -len(suffix)]
        return name

    if any(
        executable_name(fragment) in indirect_entry_points
        # POSIX shlex consumes backslashes in Windows executable paths. Scan
        # both parsed argv and raw whitespace fragments so ``C:\\...\\SH.EXE``
        # cannot lose the separator evidence before comparison.
        for token in (*tokens, *command.split())
        for fragment in token.split()
    ):
        return False
    # shlex removes quoting, so inspect punctuation inside every resulting
    # token as well as standalone operator tokens. This closes nested forms
    # such as ``bash -c 'safe; unsafe'`` and ``eval 'safe && unsafe'``.
    return not any(character in _SHELL_PUNCTUATION for token in tokens for character in token)


def _validate_subpattern(subpattern: Any) -> bool:
    """Reject ambiguous repeats and return whether this branch contains one.

    Python exposes no public regex AST. The private parser is used only as a
    conservative safety screen after compilation; if a supported interpreter
    changes its shape, tests fail and policy cannot be released silently.
    """
    previous_repeat = False
    active_repeat_atom: tuple[object, object] | None = None
    contains_repeat = False
    for operation, argument in subpattern.data:
        if operation in _REPEAT_OPS:
            _minimum, _maximum, repeated = argument
            if previous_repeat or active_repeat_atom is not None or len(repeated.data) != 1:
                raise ValueError("command pattern uses ambiguous repetition")
            repeated_operation, _repeated_argument = repeated.data[0]
            if repeated_operation not in _SAFE_REPEAT_ATOMS:
                raise ValueError("command pattern repeats an unsupported expression")
            previous_repeat = True
            active_repeat_atom = (repeated_operation, _repeated_argument)
            contains_repeat = True
            continue
        if operation is sre_constants.SUBPATTERN:
            _group, add_flags, delete_flags, nested = argument
            if add_flags or delete_flags:
                raise ValueError("command pattern uses unsupported inline flags")
            nested_repeat = _validate_subpattern(nested)
            if (previous_repeat or active_repeat_atom is not None) and nested_repeat:
                raise ValueError("command pattern uses ambiguous repetition")
            if not nested_repeat and nested.getwidth()[0] > 0:
                previous_repeat = False
                if active_repeat_atom is not None and _subpattern_starts_disjoint(
                    active_repeat_atom, nested
                ):
                    active_repeat_atom = None
            contains_repeat = contains_repeat or nested_repeat
            if nested_repeat:
                active_repeat_atom = (None, None)
            continue
        if operation is sre_constants.BRANCH:
            _none, branches = argument
            branch_repeats = [_validate_subpattern(branch) for branch in branches]
            if (previous_repeat or active_repeat_atom is not None) and any(branch_repeats):
                raise ValueError("command pattern uses ambiguous repetition")
            if not any(branch_repeats) and all(branch.getwidth()[0] > 0 for branch in branches):
                previous_repeat = False
                if active_repeat_atom is not None and all(
                    _subpattern_starts_disjoint(active_repeat_atom, branch) for branch in branches
                ):
                    active_repeat_atom = None
            contains_repeat = contains_repeat or any(branch_repeats)
            if any(branch_repeats):
                active_repeat_atom = (None, None)
            continue
        if operation in _SAFE_REPEAT_ATOMS:
            if active_repeat_atom is not None and not _atoms_may_overlap(
                active_repeat_atom, (operation, argument)
            ):
                active_repeat_atom = None
            previous_repeat = False
            continue
        if operation is sre_constants.AT:
            continue
        raise ValueError("command pattern uses unsupported regex syntax")
    return contains_repeat


def compile_command_patterns(patterns: Sequence[object]) -> tuple[Pattern[str], ...]:
    """Validate and compile a bounded set of command patterns.

    Lookarounds, inline flags, backreferences, and quantified groups are
    intentionally unsupported. They are unnecessary for the documented
    command-policy use cases and include common catastrophic-backtracking
    forms such as ``(a+)+`` and ``(a|aa)+``. Callers should surface
    ``ValueError`` as an invalid policy and fail closed.
    """
    if len(patterns) > MAX_COMMAND_PATTERN_COUNT:
        raise ValueError("command pattern list exceeds the supported limit")
    compiled: list[Pattern[str]] = []
    for pattern in patterns:
        if not isinstance(pattern, str) or not pattern or len(pattern) > MAX_COMMAND_PATTERN_LENGTH:
            raise ValueError("command pattern must be bounded non-empty text")
        if (
            "(?" in pattern
            or _BACKREFERENCE.search(pattern)
            or _NAMED_UNICODE_ESCAPE.search(pattern)
            or _QUANTIFIED_GROUP.search(pattern)
        ):
            raise ValueError("command pattern uses unsupported backtracking syntax")
        try:
            compiled_pattern = re.compile(pattern)
            parsed_pattern = sre_parser.parse(pattern, flags=0)
            _validate_subpattern(parsed_pattern)
        except (re.error, OverflowError) as exc:
            # CPython reports oversized repeat bounds as OverflowError rather
            # than re.error. Policy ingress must still receive one stable,
            # fail-closed validation error instead of an adapter/API crash.
            raise ValueError("command pattern is invalid") from exc
        compiled.append(compiled_pattern)
    return tuple(compiled)


__all__ = [
    "MAX_COMMAND_PATTERN_COUNT",
    "MAX_COMMAND_PATTERN_LENGTH",
    "MAX_COMMAND_TEXT_LENGTH",
    "command_is_single_invocation",
    "compile_command_patterns",
]

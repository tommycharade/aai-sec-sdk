"""Shared commit/worktree binding for mutation evidence."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path


def workspace_digest(source_scope: list[str]) -> str:
    """Hash mutated sources and test/tool inputs, including uncommitted files."""
    paths = {Path(value) for value in source_scope}
    paths.update(Path("tests").rglob("*.py"))
    paths.update(Path("scripts").rglob("*.py"))
    paths.update(
        {Path("pyproject.toml"), Path("mutation-baseline.json"), Path("critical-mutants.json")}
    )
    digest = hashlib.sha256()
    for path in sorted((Path(value) for value in paths), key=str):
        if not path.is_file():
            continue
        digest.update(str(path).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def target_metadata(symbol: str) -> dict[str, object]:
    """Derive stable source identity for a fully-qualified mutation symbol."""
    parts = symbol.split(".")
    if len(parts) < 3:
        raise ValueError(f"invalid mutation symbol: {symbol}")
    module_parts = parts[:-2] if parts[-2][0].isupper() else parts[:-1]
    source = Path("src") / Path(*module_parts).with_suffix(".py")
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    names = parts[len(module_parts) :]
    node: ast.AST | None = tree
    for name in names:
        if node is None:
            raise ValueError(f"mutation symbol is not defined: {symbol}")
        node = next(
            (
                child
                for child in ast.iter_child_nodes(node)
                if isinstance(child, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                and child.name == name
            ),
            None,
        )
        if node is None:
            raise ValueError(f"mutation symbol is not defined: {symbol}")
    if node is None or not isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
        raise ValueError(f"mutation symbol is not a code object: {symbol}")
    code_node = node
    if code_node.end_lineno is None:
        raise ValueError(f"mutation symbol has no source span: {symbol}")
    start = code_node.lineno
    end = code_node.end_lineno
    fingerprint = hashlib.sha256(
        json.dumps(
            {"symbol": symbol, "source": source.as_posix(), "start": start, "end": end},
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    return {
        "source": source.as_posix(),
        "source_span": {"start": start, "end": end},
        "mutation_class": "ast-node",
        "fingerprint": fingerprint,
    }

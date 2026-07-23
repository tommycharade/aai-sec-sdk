"""Repository-level checks that keep the engineering guardrails present."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "AGENTS.md",
    "CONTRIBUTING.md",
    "README.md",
    "docs/guardrails.md",
    "pyproject.toml",
    "Makefile",
)


def main() -> int:
    missing = [path for path in REQUIRED if not (ROOT / path).is_file()]
    if missing:
        print("Missing required project guardrails:")
        for path in missing:
            print(f"- {path}")
        return 1

    guardrails = (ROOT / "docs/guardrails.md").read_text(encoding="utf-8")
    required_phrases = (
        "fail-closed",
        "per action",
        "redact",
        "adversarial",
        "definition of done",
    )
    missing_phrases = [
        phrase for phrase in required_phrases if phrase.lower() not in guardrails.lower()
    ]
    if missing_phrases:
        print("Guardrails document is missing required principles:")
        for phrase in missing_phrases:
            print(f"- {phrase}")
        return 1

    print("Repository guardrails present.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

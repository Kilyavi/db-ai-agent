import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN_TRACKED_PATHS = [
    ".env",
    "AGENTS.md",
    "agent_rules.json",
    "config/personal_config.json",
    "config/personal_agent_config.json",
]

FORBIDDEN_TRACKED_PREFIXES = [
    ".agents/",
    ".codex/",
    ".idea/",
    "reports/",
    "dist/",
    "deterministic_pipeline/reports/",
    ".venv/",
    "__pycache__/",
]

SECRET_PATTERNS = [
    re.compile(r"CH_PASSWORD\s*=\s*.+", re.IGNORECASE),
    re.compile(r'"password"\s*:\s*"[^"]{3,}"', re.IGNORECASE),
    re.compile(r"OPENAI_API_KEY\s*=\s*sk-[A-Za-z0-9_-]+", re.IGNORECASE),
    re.compile(r"AI_AGENT_API_KEY\s*=\s*.+", re.IGNORECASE),
    re.compile(r"Authorization:\s*Bearer\s+[A-Za-z0-9._-]+", re.IGNORECASE),
    re.compile(r"C:[/\\]Users[/\\][^/\\\s]+", re.IGNORECASE),
]

TEXT_SUFFIXES = {
    ".py",
    ".md",
    ".json",
    ".txt",
    ".toml",
    ".yaml",
    ".yml",
    ".env",
}


def git_commit_candidate_files() -> tuple[list[str], bool]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    if result.returncode != 0:
        print("Not inside a git repository or git is not available.")
        print(result.stderr.strip())
        return [], False

    return [
        line.strip().replace("\\", "/")
        for line in result.stdout.splitlines()
        if line.strip()
    ], True


def is_forbidden_path(path: str) -> bool:
    if path in FORBIDDEN_TRACKED_PATHS:
        return True

    return any(path.startswith(prefix) for prefix in FORBIDDEN_TRACKED_PREFIXES)


def scan_file(path: str) -> list[str]:
    full_path = ROOT / path
    if full_path.suffix.lower() not in TEXT_SUFFIXES:
        return []

    try:
        text = full_path.read_text(encoding="utf-8")
    except Exception:
        return []

    findings = []
    for pattern in SECRET_PATTERNS:
        if pattern.search(text):
            findings.append(f"{path}: possible secret matched {pattern.pattern}")

    return findings


def main() -> int:
    candidates, git_ok = git_commit_candidate_files()
    if not git_ok:
        return 2

    problems = []

    for path in candidates:
        if is_forbidden_path(path):
            problems.append(f"{path}: should not be tracked")
        problems.extend(scan_file(path))

    if problems:
        print("Git safety check failed:")
        for problem in problems:
            print(f"- {problem}")
        return 1

    print("Git safety check passed for commit-candidate files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

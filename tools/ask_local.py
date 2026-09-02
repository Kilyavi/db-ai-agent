#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
import urllib.request
import urllib.error

DEFAULT_BASE_URL = "http://localhost:1234/v1"
DEFAULT_MODEL = "openai/gpt-oss-20b"
DEFAULT_MODEL_IDENTIFIER = "codex-local-worker-gpt-oss"
DEFAULT_CONTEXT_LENGTH = 65536
DEFAULT_GPU_OFFLOAD = "max"
DEFAULT_PARALLEL = 1
DEFAULT_MAX_INPUT_CHARS = 160000
DEFAULT_MAX_OUTPUT_TOKENS = 12000
DEFAULT_LMS_TIMEOUT_SECONDS = 240

BLOCKED_NAME_PARTS = [
    ".env",
    "secret",
    "secrets",
    "credential",
    "credentials",
    "token",
    "tokens",
    "private_key",
    "id_rsa",
]


class LocalWorkerError(RuntimeError):
    pass


def fail(message: str, code: int = 1) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(code)


def is_blocked_path(path: Path) -> bool:
    normalized = str(path).replace("\\", "/").lower()
    return any(part in normalized for part in BLOCKED_NAME_PARTS)


def read_input(args: argparse.Namespace) -> tuple[str, str]:
    if args.file:
        path = Path(args.file)
        if not path.exists():
            fail(f"file does not exist: {path}")
        if not path.is_file():
            fail(f"path is not a file: {path}")
        if is_blocked_path(path):
            fail(f"refusing to read sensitive-looking file: {path}")

        text = path.read_text(encoding="utf-8", errors="replace")
        source = str(path)
    else:
        text = sys.stdin.read()
        source = "stdin"

    max_chars = args.max_input_chars
    if len(text) > max_chars:
        text = text[:max_chars] + "\n\n[TRUNCATED_BY_LOCAL_WORKER_INPUT_LIMIT]\n"

    return source, text


def run_lms(arguments: list[str], timeout: int = DEFAULT_LMS_TIMEOUT_SECONDS) -> str:
    command = ["lms", *arguments]
    try:
        result = subprocess.run(
            command,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise LocalWorkerError(
            "LM Studio CLI 'lms' was not found. Install/enable it before using the local worker."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise LocalWorkerError(
            f"LM Studio command timed out after {timeout}s: {' '.join(command)}"
        ) from exc

    if result.returncode != 0:
        details = (result.stderr or result.stdout).strip()
        raise LocalWorkerError(
            f"LM Studio command failed with exit code {result.returncode}: "
            f"{' '.join(command)}\n{details}"
        )
    return result.stdout.strip()


def get_loaded_models() -> list[str]:
    raw = run_lms(["ps", "--json"])
    try:
        payload = json.loads(raw or "[]")
    except json.JSONDecodeError as exc:
        raise LocalWorkerError(f"Unexpected response from 'lms ps --json': {raw}") from exc

    if not isinstance(payload, list):
        raise LocalWorkerError(f"Unexpected response from 'lms ps --json': {raw}")
    return [
        str(item.get("identifier") or item.get("modelKey") or item.get("path") or "unknown")
        for item in payload
        if isinstance(item, dict)
    ]


def load_model(
    model: str,
    identifier: str,
    context_length: int,
    gpu_offload: str,
    parallel: int,
    replace_loaded: bool = False,
) -> None:
    loaded_models = get_loaded_models()
    if loaded_models:
        if not replace_loaded:
            raise LocalWorkerError(
                "Refusing to load the local worker while another model is loaded: "
                + ", ".join(loaded_models)
            )
        for loaded_identifier in loaded_models:
            unload_model(loaded_identifier)

    arguments = [
        "load",
        model,
        "--context-length",
        str(context_length),
        "--gpu",
        gpu_offload,
        "--parallel",
        str(parallel),
        "--identifier",
        identifier,
    ]
    arguments.append("--yes")
    run_lms(arguments)


def unload_model(identifier: str) -> None:
    run_lms(["unload", identifier])


def call_lmstudio(
    base_url: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
    max_output_tokens: int,
) -> str:
    url = base_url.rstrip("/") + "/chat/completions"

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.1,
        "max_tokens": max_output_tokens,
    }

    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        fail(f"LM Studio request failed: {exc}")

    try:
        parsed = json.loads(raw)
        return parsed["choices"][0]["message"]["content"]
    except Exception:
        fail(f"unexpected LM Studio response:\n{raw}")


def run_loaded_worker(
    *,
    base_url: str,
    model: str,
    identifier: str,
    context_length: int,
    gpu_offload: str,
    parallel: int,
    system_prompt: str,
    user_prompt: str,
    max_output_tokens: int,
) -> str:
    print(
        f"Loading {model} with context={context_length}, gpu={gpu_offload}, parallel={parallel}...",
        file=sys.stderr,
        flush=True,
    )
    load_model(
        model=model,
        identifier=identifier,
        context_length=context_length,
        gpu_offload=gpu_offload,
        parallel=parallel,
        replace_loaded=True,
    )
    try:
        return call_lmstudio(
            base_url=base_url,
            model=identifier,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_output_tokens=max_output_tokens,
        )
    finally:
        print(f"Unloading {identifier}...", file=sys.stderr, flush=True)
        unload_model(identifier)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Small bounded LM Studio worker for Codex routine tasks."
    )
    parser.add_argument("--task", required=True, help="Narrow task for the local model.")
    parser.add_argument("--file", help="Optional single file to include.")
    parser.add_argument(
        "--max-input-chars",
        type=int,
        default=DEFAULT_MAX_INPUT_CHARS,
        help=f"Maximum input characters sent to local model. Default: {DEFAULT_MAX_INPUT_CHARS}",
    )
    parser.add_argument(
        "--max-output-tokens",
        type=int,
        default=DEFAULT_MAX_OUTPUT_TOKENS,
        help=f"Maximum output tokens. Default: {DEFAULT_MAX_OUTPUT_TOKENS}",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("LOCAL_WORKER_MODEL", DEFAULT_MODEL),
        help=f"LM Studio model id. Default: {DEFAULT_MODEL}",
    )
    parser.add_argument(
        "--identifier",
        default=os.environ.get("LOCAL_WORKER_IDENTIFIER", DEFAULT_MODEL_IDENTIFIER),
        help=f"Temporary API identifier for the loaded worker. Default: {DEFAULT_MODEL_IDENTIFIER}",
    )
    parser.add_argument(
        "--context-length",
        type=int,
        default=int(os.environ.get("LOCAL_WORKER_CONTEXT_LENGTH", DEFAULT_CONTEXT_LENGTH)),
        help=f"LM Studio context length. Default: {DEFAULT_CONTEXT_LENGTH}",
    )
    parser.add_argument(
        "--gpu",
        default=os.environ.get("LOCAL_WORKER_GPU", DEFAULT_GPU_OFFLOAD),
        help=f"LM Studio GPU offload ratio. Default: {DEFAULT_GPU_OFFLOAD}",
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=int(os.environ.get("LOCAL_WORKER_PARALLEL", DEFAULT_PARALLEL)),
        help=f"LM Studio parallel prediction count. Default: {DEFAULT_PARALLEL}",
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("LMSTUDIO_BASE_URL", DEFAULT_BASE_URL),
        help=f"LM Studio OpenAI-compatible base URL. Default: {DEFAULT_BASE_URL}",
    )

    args = parser.parse_args()

    source, text = read_input(args)

    system_prompt = """You are a local bounded coding helper.

Rules:
- Work only with the provided snippet/file.
- Do not assume full repository context.
- Do not make architecture, security, or database-safety decisions.
- For SQL, only suggest read-only SELECT/WITH/SHOW/DESCRIBE/EXPLAIN.
- Never suggest INSERT, UPDATE, DELETE, DROP, ALTER, TRUNCATE, CREATE, OPTIMIZE, GRANT, REVOKE, SET, or USE.
- Keep output concise.
- Return: Findings, Suggested change if any, Risks/checks.
"""

    user_prompt = f"""Task:
{args.task}

Source:
{source}

Content:
{text}
"""

    try:
        answer = run_loaded_worker(
            base_url=args.base_url,
            model=args.model,
            identifier=args.identifier,
            context_length=args.context_length,
            gpu_offload=args.gpu,
            parallel=args.parallel,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_output_tokens=args.max_output_tokens,
        )
    except LocalWorkerError as exc:
        fail(str(exc))

    print(answer.strip())


if __name__ == "__main__":
    main()

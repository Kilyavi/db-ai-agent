import argparse
import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "dist" / "deterministic-quality.zip"
ARCHIVE_ROOT = "deterministic-quality"
ZIP_TIME = (1980, 1, 1, 0, 0, 0)

REQUIRED_FILES = (
    "quality_config.py",
    "config/system_agent_config.json",
    "config/personal_agent_config.example.json",
    "config/personal_config.example.json",
    "deterministic_pipeline/README.md",
    "deterministic_pipeline/requirements.txt",
    "deterministic_pipeline/run_pipeline.py",
)
REQUIRED_GLOBS = (
    "deterministic_pipeline/lib/*.py",
    "deterministic_pipeline/scripts/*.py",
)
FORBIDDEN_PARTS = {".git", ".github", "__pycache__", "reports"}
FORBIDDEN_NAMES = {
    ".env",
    ".gitignore",
    "personal_config.json",
}
SENSITIVE_KEYS = {
    "password",
    "api_key",
    "secret",
    "token",
    "access_key",
    "private_key",
}


def package_files(root: Path = ROOT) -> list[Path]:
    files = [root / relative for relative in REQUIRED_FILES]
    for pattern in REQUIRED_GLOBS:
        files.extend(root.glob(pattern))

    missing = [str(path.relative_to(root)) for path in files if not path.is_file()]
    if missing:
        raise FileNotFoundError("Missing required package files: " + ", ".join(missing))

    unique = sorted(set(files), key=lambda path: path.as_posix())
    for path in unique:
        relative = path.relative_to(root)
        if FORBIDDEN_PARTS.intersection(relative.parts):
            raise ValueError(f"Forbidden directory in package: {relative}")
        if relative.name in FORBIDDEN_NAMES or relative.suffix == ".pyc":
            raise ValueError(f"Forbidden file in package: {relative}")
    return unique


def validate_agent_config_payload(config: dict) -> None:
    active_profile = config.get("active_database_profile")
    if not isinstance(active_profile, str) or not active_profile.strip():
        raise ValueError("Share config must define active_database_profile")
    profile = config.get("database_profiles", {}).get(active_profile, {})
    if not isinstance(profile, dict):
        raise ValueError(f"Share config must define profile {active_profile}")
    for key in ("kind", "database", "main_identifier"):
        if not isinstance(profile.get(key), str) or not profile[key].strip():
            raise ValueError(f"Share profile must define {key}")

    def walk(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if str(key).lower() in SENSITIVE_KEYS:
                    raise ValueError(f"Sensitive key is forbidden in shared agent config: {key}")
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(config)


def release_agent_config(path: Path) -> bytes:
    config = json.loads(path.read_text(encoding="utf-8"))
    validate_agent_config_payload(config)
    return (
        json.dumps(config, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def build_zip(output: Path = DEFAULT_OUTPUT, root: Path = ROOT) -> Path:
    files = package_files(root)
    agent_config_bytes = release_agent_config(
        root / "config" / "personal_agent_config.example.json"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        output,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for source in files:
            relative = source.relative_to(root).as_posix()
            archive_relative = (
                "config/personal_agent_config.json"
                if relative == "config/personal_agent_config.example.json"
                else relative
            )
            info = zipfile.ZipInfo(f"{ARCHIVE_ROOT}/{archive_relative}", ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            content = (
                agent_config_bytes
                if relative == "config/personal_agent_config.example.json"
                else source.read_bytes()
            )
            archive.writestr(info, content, compresslevel=9)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build the minimal credential-free deterministic pipeline ZIP."
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    print(build_zip(args.output.resolve()))


if __name__ == "__main__":
    main()

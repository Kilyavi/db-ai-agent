import subprocess
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "dist" / f"{ROOT.name}.zip"
ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def shareable_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return sorted(path for path in result.stdout.decode("utf-8").split("\0") if path)


def main() -> None:
    OUTPUT.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(
        OUTPUT,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for relative_path in shareable_files():
            source = ROOT / relative_path
            if not source.is_file():
                continue
            info = zipfile.ZipInfo(f"{ROOT.name}/{relative_path}", ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, source.read_bytes(), compresslevel=9)
    print(OUTPUT)


if __name__ == "__main__":
    main()

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

try:
    from .lib.artifacts import atomic_write_text
except ImportError:  # Direct script execution from deterministic_pipeline/.
    from lib.artifacts import atomic_write_text


PROJECT_DIR = Path(__file__).resolve().parent
REPORT_DIR = PROJECT_DIR / "reports"
REPORT_DIR.mkdir(exist_ok=True)
DEGRADED_RETURN_CODE = 2

SCRIPTS = [
    ("Collect metrics", PROJECT_DIR / "scripts" / "collect_metrics.py"),
    ("Collect drilldowns", PROJECT_DIR / "scripts" / "collect_drilldowns.py"),
    ("Build report", PROJECT_DIR / "scripts" / "build_report.py"),
]


def format_reference_time(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.astimezone()
    return value.isoformat(timespec="seconds")


def run_script(
    name: str,
    path: Path,
    run_id: str | None = None,
    reference_time: str | None = None,
) -> dict:
    started_at = datetime.now()
    print("\n" + "=" * 80)
    print(name)
    print(path)
    print("=" * 80)

    environment = os.environ.copy()
    if run_id:
        environment["DQ_RUN_ID"] = run_id
    if reference_time:
        environment["QUALITY_REFERENCE_TIME"] = reference_time

    result = subprocess.run(
        [sys.executable, str(path)],
        cwd=str(PROJECT_DIR),
        env=environment,
    )

    finished_at = datetime.now()
    return {
        "name": name,
        "script": str(path),
        "started_at": str(started_at),
        "finished_at": str(finished_at),
        "duration_seconds": round((finished_at - started_at).total_seconds(), 3),
        "returncode": result.returncode,
        "status": (
            "ok"
            if result.returncode == 0
            else "degraded"
            if result.returncode == DEGRADED_RETURN_CODE
            else "failed"
        ),
    }


def main():
    started_at = datetime.now()
    run_id = started_at.strftime("%Y%m%d_%H%M%S")
    reference_time = format_reference_time(started_at)
    stages = []

    print(f"Deterministic pipeline started at: {started_at}")

    for name, path in SCRIPTS:
        stage = run_script(name, path, run_id, reference_time)
        stages.append(stage)
        if stage["status"] == "failed":
            break

    finished_at = datetime.now()
    failed_stage = next((stage for stage in stages if stage["status"] == "failed"), None)
    degraded_stages = [stage for stage in stages if stage["status"] == "degraded"]
    manifest = {
        "pipeline": "deterministic_quality_pipeline",
        "run_id": run_id,
        "reference_time": reference_time,
        "started_at": str(started_at),
        "finished_at": str(finished_at),
        "duration_seconds": round((finished_at - started_at).total_seconds(), 3),
        "status": "failed" if failed_stage else "degraded" if degraded_stages else "ok",
        "failed_stage": failed_stage,
        "degraded_stages": degraded_stages,
        "stages": stages,
    }

    manifest_path = REPORT_DIR / f"pipeline_run_{run_id}.json"
    stable_manifest_path = REPORT_DIR / "pipeline_run.json"
    text = json.dumps(manifest, indent=2, ensure_ascii=False)
    atomic_write_text(manifest_path, text)
    atomic_write_text(stable_manifest_path, text)

    print("\n" + "=" * 80)
    print(f"Finished at: {finished_at}")
    print(f"Status: {manifest['status']}")
    print(f"Manifest: {manifest_path}")
    print("=" * 80)

    if failed_stage:
        raise RuntimeError(f"{failed_stage['script']} failed with exit code {failed_stage['returncode']}")
    if degraded_stages:
        raise SystemExit(DEGRADED_RETURN_CODE)


if __name__ == "__main__":
    main()

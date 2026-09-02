import json
import os
import subprocess
import sys
from contextlib import ExitStack, contextmanager
from datetime import datetime
from pathlib import Path

from tools.ask_local import (
    DEFAULT_CONTEXT_LENGTH,
    DEFAULT_GPU_OFFLOAD,
    DEFAULT_MODEL,
    DEFAULT_PARALLEL,
    load_model,
    unload_model,
)


PROJECT_DIR = Path(__file__).resolve().parent
REPORT_DIR = PROJECT_DIR / "reports"
REPORT_DIR.mkdir(exist_ok=True)

DEGRADED_RETURN_CODE = 2
PIPELINE_LLM_IDENTIFIER = "quality-pipeline-gpt-oss"

STAGES = [
    {
        "name": "Deterministic DB baseline scan",
        "script": "scan_database_quality.py",
    },
    {
        "name": "Deterministic event quality checks",
        "script": "check_event_quality.py",
    },
    {
        "name": "Configurable parameter quality checks",
        "script": "check_parameter_quality.py",
    },
    {
        "name": "Raw-to-parsed event flow and DLQ checks",
        "script": "check_event_flow.py",
    },
    {
        "name": "Problem drilldowns",
        "script": "drill_down_quality_issues.py",
    },
    {
        "name": "AI-led evidence-guided DB investigation",
        "script": "investigate_database.py",
        "uses_llm": True,
    },
    {
        "name": "LLM final report",
        "script": "generate_quality_report.py",
        "uses_llm": True,
    },
]


def format_reference_time(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.astimezone()
    return value.isoformat(timespec="seconds")


def run_script(
    stage: dict,
    run_id: str | None = None,
    reference_time: str | None = None,
    llm_model_identifier: str | None = None,
) -> dict:
    script_name = stage["script"]
    script_path = PROJECT_DIR / script_name
    started_at = datetime.now()

    print("\n" + "=" * 80)
    print(f"Stage: {stage['name']}")
    print(f"Running: {script_name}")
    print("=" * 80)

    environment = os.environ.copy()
    if run_id:
        environment["QUALITY_RUN_ID"] = run_id
    if reference_time:
        environment["QUALITY_REFERENCE_TIME"] = reference_time
    if llm_model_identifier:
        environment["AI_AGENT_MODEL"] = llm_model_identifier
        environment["LMSTUDIO_MODEL"] = llm_model_identifier

    result = subprocess.run(
        [sys.executable, str(script_path)],
        cwd=PROJECT_DIR,
        env=environment,
    )

    finished_at = datetime.now()

    return {
        "name": stage["name"],
        "script": script_name,
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


@contextmanager
def managed_pipeline_llm():
    print(
        "Loading pipeline LLM: "
        f"{DEFAULT_MODEL} (context={DEFAULT_CONTEXT_LENGTH}, "
        f"gpu={DEFAULT_GPU_OFFLOAD}, parallel={DEFAULT_PARALLEL})"
    )
    load_model(
        model=DEFAULT_MODEL,
        identifier=PIPELINE_LLM_IDENTIFIER,
        context_length=DEFAULT_CONTEXT_LENGTH,
        gpu_offload=DEFAULT_GPU_OFFLOAD,
        parallel=DEFAULT_PARALLEL,
        replace_loaded=True,
    )
    try:
        yield PIPELINE_LLM_IDENTIFIER
    finally:
        print(f"Unloading pipeline LLM: {PIPELINE_LLM_IDENTIFIER}")
        unload_model(PIPELINE_LLM_IDENTIFIER)


def main():
    started_at = datetime.now()
    run_id = started_at.strftime("%Y%m%d_%H%M%S")
    reference_time = format_reference_time(started_at)
    manifest_path = REPORT_DIR / f"quality_agent_run_{run_id}.json"

    print(f"Quality agent started at: {started_at}")
    print("Pipeline:")
    for index, stage in enumerate(STAGES, start=1):
        print(f"{index}. {stage['name']} ({stage['script']})")

    stage_results = []

    with ExitStack() as llm_stack:
        llm_model_identifier = None
        for stage in STAGES:
            if stage.get("uses_llm") and llm_model_identifier is None:
                llm_model_identifier = llm_stack.enter_context(managed_pipeline_llm())

            stage_result = run_script(
                stage,
                run_id,
                reference_time,
                llm_model_identifier if stage.get("uses_llm") else None,
            )
            stage_results.append(stage_result)

            if stage_result["status"] == "failed":
                break

    finished_at = datetime.now()
    failed_stage = next(
        (stage for stage in stage_results if stage["status"] == "failed"),
        None,
    )
    degraded_stages = [
        stage for stage in stage_results if stage["status"] == "degraded"
    ]

    manifest = {
        "agent": "quality_agent",
        "run_id": run_id,
        "reference_time": reference_time,
        "started_at": str(started_at),
        "finished_at": str(finished_at),
        "duration_seconds": round((finished_at - started_at).total_seconds(), 3),
        "status": "failed" if failed_stage else "degraded" if degraded_stages else "ok",
        "failed_stage": failed_stage,
        "degraded_stages": degraded_stages,
        "stages": stage_results,
    }

    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("\n" + "=" * 80)
    print(f"Quality agent finished at: {finished_at}")
    print(f"Duration: {finished_at - started_at}")
    print(f"Run manifest: {manifest_path}")
    print("=" * 80)

    if failed_stage:
        raise RuntimeError(
            f"{failed_stage['script']} failed with exit code {failed_stage['returncode']}"
        )
    if degraded_stages:
        raise SystemExit(DEGRADED_RETURN_CODE)


if __name__ == "__main__":
    main()

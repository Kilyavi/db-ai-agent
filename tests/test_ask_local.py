import importlib.util
import unittest
from pathlib import Path
from unittest.mock import call, patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "ask_local.py"
SPEC = importlib.util.spec_from_file_location("ask_local", MODULE_PATH)
ask_local = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(ask_local)


class AskLocalLifecycleTests(unittest.TestCase):
    def test_finalized_gpt_oss_defaults(self):
        self.assertEqual("openai/gpt-oss-20b", ask_local.DEFAULT_MODEL)
        self.assertEqual(65536, ask_local.DEFAULT_CONTEXT_LENGTH)
        self.assertEqual("max", ask_local.DEFAULT_GPU_OFFLOAD)
        self.assertEqual(1, ask_local.DEFAULT_PARALLEL)
        self.assertEqual(160000, ask_local.DEFAULT_MAX_INPUT_CHARS)
        self.assertEqual(12000, ask_local.DEFAULT_MAX_OUTPUT_TOKENS)

    def test_load_model_uses_optimized_settings(self):
        with patch.object(ask_local, "run_lms", side_effect=["[]", ""]) as run_lms:
            ask_local.load_model(
                model="openai/gpt-oss-20b",
                identifier="worker-id",
                context_length=65536,
                gpu_offload="max",
                parallel=1,
            )

        self.assertEqual(call(["ps", "--json"]), run_lms.call_args_list[0])
        self.assertEqual(
            call(
                [
                    "load",
                    "openai/gpt-oss-20b",
                    "--context-length",
                    "65536",
                    "--gpu",
                    "max",
                    "--parallel",
                    "1",
                    "--identifier",
                    "worker-id",
                    "--yes",
                ]
            ),
            run_lms.call_args_list[1],
        )

    def test_load_model_refuses_to_stack_on_loaded_model(self):
        loaded = '[{"identifier": "already-loaded"}]'
        with patch.object(ask_local, "run_lms", return_value=loaded) as run_lms:
            with self.assertRaisesRegex(
                ask_local.LocalWorkerError,
                "another model is loaded: already-loaded",
            ):
                ask_local.load_model(
                    model="openai/gpt-oss-20b",
                    identifier="worker-id",
                    context_length=65536,
                    gpu_offload="max",
                    parallel=1,
                )

        run_lms.assert_called_once_with(["ps", "--json"])

    def test_load_model_replaces_stale_model_when_requested(self):
        loaded = '[{"identifier": "google/gemma-4-e4b"}]'
        with patch.object(ask_local, "run_lms", side_effect=[loaded, "", ""]) as run_lms:
            ask_local.load_model(
                model="openai/gpt-oss-20b",
                identifier="worker-id",
                context_length=65536,
                gpu_offload="max",
                parallel=1,
                replace_loaded=True,
            )

        self.assertEqual(call(["ps", "--json"]), run_lms.call_args_list[0])
        self.assertEqual(
            call(["unload", "google/gemma-4-e4b"]),
            run_lms.call_args_list[1],
        )
        self.assertEqual("load", run_lms.call_args_list[2].args[0][0])

    def test_worker_unloads_after_success(self):
        with (
            patch.object(ask_local, "load_model") as load_model,
            patch.object(ask_local, "call_lmstudio", return_value="answer") as inference,
            patch.object(ask_local, "unload_model") as unload_model,
        ):
            result = ask_local.run_loaded_worker(
                base_url=ask_local.DEFAULT_BASE_URL,
                model=ask_local.DEFAULT_MODEL,
                identifier="worker-id",
                context_length=65536,
                gpu_offload="max",
                parallel=1,
                system_prompt="system",
                user_prompt="user",
                max_output_tokens=12000,
            )

        self.assertEqual("answer", result)
        load_model.assert_called_once()
        inference.assert_called_once_with(
            base_url=ask_local.DEFAULT_BASE_URL,
            model="worker-id",
            system_prompt="system",
            user_prompt="user",
            max_output_tokens=12000,
        )
        unload_model.assert_called_once_with("worker-id")

    def test_worker_unloads_after_inference_failure(self):
        with (
            patch.object(ask_local, "load_model"),
            patch.object(ask_local, "call_lmstudio", side_effect=RuntimeError("failed")),
            patch.object(ask_local, "unload_model") as unload_model,
        ):
            with self.assertRaisesRegex(RuntimeError, "failed"):
                ask_local.run_loaded_worker(
                    base_url=ask_local.DEFAULT_BASE_URL,
                    model=ask_local.DEFAULT_MODEL,
                    identifier="worker-id",
                    context_length=65536,
                    gpu_offload="max",
                    parallel=1,
                    system_prompt="system",
                    user_prompt="user",
                    max_output_tokens=12000,
                )

        unload_model.assert_called_once_with("worker-id")


if __name__ == "__main__":
    unittest.main()

import os
import sys
import threading
import time


DISABLED_VALUES = {"0", "false", "no", "off"}


def spinner_enabled() -> bool:
    value = os.getenv("DB_AGENT_SPINNER", "1").strip().lower()
    if value in DISABLED_VALUES:
        return False
    if value in {"auto", "tty"}:
        return spinner_stream().isatty()
    return True


def spinner_stream():
    value = os.getenv("DB_AGENT_SPINNER_STREAM", "stdout").strip().lower()
    if value == "stderr":
        return sys.stderr
    return sys.stdout


class Spinner:
    def __init__(self, message: str, interval: float = 0.12):
        self.message = message
        self.interval = interval
        self.enabled = spinner_enabled()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._started_at = 0.0
        self._last_len = 0
        self._stream = spinner_stream()

    def __enter__(self):
        if not self.enabled:
            return self

        self._started_at = time.monotonic()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        if not self.enabled:
            return False

        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
        self._clear()
        return False

    def _spin(self) -> None:
        frames = "|/-\\"
        index = 0

        while not self._stop.is_set():
            elapsed = time.monotonic() - self._started_at
            text = f"{frames[index % len(frames)]} {self.message} ({elapsed:0.1f}s)"
            self._write(text)
            index += 1
            self._stop.wait(self.interval)

    def _write(self, text: str) -> None:
        self._last_len = max(self._last_len, len(text))
        self._stream.write("\r" + text.ljust(self._last_len))
        self._stream.flush()

    def _clear(self) -> None:
        self._stream.write("\r" + (" " * self._last_len) + "\r")
        self._stream.flush()

"""
live_log_reader.py
==================
Lightweight generator yielding (line_number, line) from a log file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, Tuple


class LiveLogReader:
    """Reads a file line-by-line yielding (line_number, line)."""

    def __init__(self, file_path: Path | str) -> None:
        self.file_path = Path(file_path)

    def __iter__(self) -> Iterator[Tuple[int, str]]:
        if not self.file_path.exists():
            return
        with open(self.file_path, "r", encoding="utf-8", errors="replace") as f:
            for line_number, line in enumerate(f, start=1):
                yield line_number, line.rstrip("\r\n")

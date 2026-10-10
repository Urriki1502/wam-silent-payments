"""Cross-process test helper: run under the selected Python architecture."""

import importlib.util
from pathlib import Path
import sys

module_path, lock_path, ready_path = sys.argv[1:]
spec = importlib.util.spec_from_file_location("scanner_lock_child", module_path)
if spec is None or spec.loader is None:
    raise RuntimeError("LOCK_MODULE_LOAD_FAILED")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

with module.exclusive_file_lock(lock_path):
    Path(ready_path).write_text("LOCKED", encoding="ascii")
    sys.stdin.buffer.read(1)

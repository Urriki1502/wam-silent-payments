from pathlib import Path
import sys
import tempfile
import unittest
from devtools.conformance import run
from devtools.qualification import release_gate, source_digest


class ReleaseGate(unittest.TestCase):
    def test_external_nonconforming_adapter_fails(self):
        root = Path(__file__).resolve().parents[1]
        command = [
            sys.executable,
            "-u",
            "-c",
            'import sys;\nfor line in sys.stdin: print(\'{"ok":false,"error":"REJECTED"}\',flush=True)',
        ]
        report = run(root, command)
        self.assertEqual(report["result"], "WSP-1 NON-CONFORMANT")
        self.assertGreater(report["failed"], 100)

    def test_missing_evidence_never_soft_passes(self):
        with tempfile.TemporaryDirectory() as d:
            gate = release_gate(d)
            self.assertEqual(gate["result"], "FAIL")
            self.assertEqual(gate["engineering"], "FAIL")

    def test_source_digest_changes_when_code_changes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for name in ("pyproject.toml", "requirements-lock.txt", "requirements-dev.txt"):
                (root / name).write_text("fixture")
            (root / "src").mkdir()
            path = root / "src/module.py"
            path.write_text("x=1")
            before = source_digest(root)
            path.write_text("x=2")
            self.assertNotEqual(before, source_digest(root))

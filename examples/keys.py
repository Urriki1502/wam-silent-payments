"""Synthetic local key lifecycle demonstration; never fund these public constants."""

from tempfile import TemporaryDirectory
from pathlib import Path
from wam_sp.keystore import Keyring, export_scan, import_scan, save_private, load_private

# Demonstration constants only. Production key custody is outside this release.
ring = Keyring(bytes(range(32)))
ring.add_label(0, 7)
ring.rotate(birthday=100)
password = b"synthetic example passphrase only"
with TemporaryDirectory() as directory:
    path = Path(directory) / "keys.enc"
    save_private(path, ring.backup(password))
    restored = Keyring.restore(load_private(path), password)
    assert restored.accounts() == ring.accounts()
    scan_only = import_scan(export_scan(restored.accounts(), password), password)
    assert not hasattr(scan_only[0], "spend_secret")
print("Encrypted recovery / rotation / scan-only export: PASS")

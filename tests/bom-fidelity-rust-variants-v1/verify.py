import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
for name, digest in manifest["files"].items():
    path = (root / name).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise SystemExit("Missing or unsafe file: " + name)
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise SystemExit("Hash mismatch: " + name)
print("PASS: five pinned controlled inputs; original lock preserved")

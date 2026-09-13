"""Package the previously built extension; run npm run build:extension first."""
from pathlib import Path
import json
import zipfile

root = Path(__file__).resolve().parent.parent
build = root / "dist/chrome-extension"
if not (build / "manifest.json").is_file():
    raise SystemExit("Run npm run build:extension first.")
# Fail rather than release a stale build.
for source in [root / "extension", root / "shared"]:
    for file in source.rglob("*"):
        if file.is_file():
            relative = file.relative_to(source)
            target = build / relative if source.name == "extension" else build / "shared" / relative
            if not target.is_file() or target.read_bytes() != file.read_bytes():
                raise SystemExit("Build is stale. Run npm run build:extension first.")
version = json.loads((build / "manifest.json").read_text())["version"]
release = root / "releases" / f"ai-shield-chrome-{version}.zip"
release.parent.mkdir(exist_ok=True)
with zipfile.ZipFile(release, "w", zipfile.ZIP_DEFLATED) as archive:
    for file in sorted(build.rglob("*")):
        if file.is_file():
            info = zipfile.ZipInfo(file.relative_to(build).as_posix(), (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, file.read_bytes())
(root / "dist/ai-shield-chrome.zip").write_bytes(release.read_bytes())
print(release)

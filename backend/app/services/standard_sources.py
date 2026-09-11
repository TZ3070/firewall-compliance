import json
from pathlib import Path

from app.models.compliance import StandardSourceFile


STANDARD_PDF_MANIFEST_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "catalog"
    / "standard-pdf-manifest-v1.json"
)


def load_standard_sources(
    manifest_path: Path = STANDARD_PDF_MANIFEST_PATH,
) -> tuple[StandardSourceFile, ...]:
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    return tuple(
        StandardSourceFile.model_validate(item) for item in payload["sources"]
    )

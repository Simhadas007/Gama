from pathlib import Path
from urllib.parse import urlparse


def detect_source_type(source: str):
    parsed = urlparse(source)

    if parsed.scheme in ["http", "https"]:
        path = parsed.path.lower()

        if path.endswith(".whl"):
            return "URL_WHEEL"
        if path.endswith(".zip"):
            return "URL_ZIP"
        if path.endswith(".exe"):
            return "URL_EXE"
        if path.endswith(".msi"):
            return "URL_MSI"

        return "URL_UNKNOWN"

    local_path = Path(source)

    if local_path.exists():
        suffix = local_path.suffix.lower()

        if suffix == ".whl":
            return "LOCAL_WHEEL"
        if suffix == ".zip":
            return "LOCAL_ZIP"
        if suffix == ".exe":
            return "LOCAL_EXE"
        if suffix == ".msi":
            return "LOCAL_MSI"

        return "LOCAL_UNKNOWN"

    return "PYPI_PACKAGE"
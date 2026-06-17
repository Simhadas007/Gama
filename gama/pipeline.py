from pathlib import Path
import tempfile
import shutil
import time
import json
import os

from gama.universal_fetcher import fetch_to_stream, detect_source


MAX_STREAM_SIZE_MB = 2048  # 2 GB limit for stream size to prevent abuse and ensure performance


class PipelineError(Exception):
    pass


def create_os_stream():
    """
    Creates a temporary OS stream directory.
    Nothing is installed on the host here.
    Files are only staged for scan/sandbox.
    """

    stream_path = Path(
        tempfile.mkdtemp(prefix="gama_stream_")
    )

    return stream_path


def validate_stream_path(stream_path: Path):
    """
    Prevent unsafe paths from being used.
    """

    if not stream_path:
        raise PipelineError("Stream path is empty")

    stream_path = Path(stream_path)

    if not stream_path.exists():
        raise PipelineError("Stream path does not exist")

    if not stream_path.is_dir():
        raise PipelineError("Stream path is not a directory")

    return True


def fetch_package(source: str, stream_path: Path, mode: str = "auto"):
    """
    Main universal fetch function.

    Supports:
    - PyPI package
    - URL
    - Local file
    - GitHub repo
    - NPM package
    - Winget metadata
    - Chocolatey metadata
    """

    validate_stream_path(stream_path)

    if not source or not source.strip():
        return False, "", "Empty target/source provided"

    source = source.strip()

    source_type = detect_source(source, mode)

    started_at = time.time()

    ok, out, err = fetch_to_stream(
        source=source,
        stream_path=stream_path,
        mode=mode
    )

    ended_at = time.time()

    metadata = {
        "source": source,
        "source_type": source_type,
        "mode": mode,
        "success": ok,
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_seconds": round(ended_at - started_at, 3),
        "stdout": out,
        "stderr": err,
        "stream_path": str(stream_path),
        "files": get_stream_file_metadata(stream_path),
        "total_size_bytes": get_stream_size(stream_path)
    }

    write_pipeline_metadata(stream_path, metadata)

    if not ok:
        return False, out, err

    size_mb = metadata["total_size_bytes"] / (1024 * 1024)

    if size_mb > MAX_STREAM_SIZE_MB:
        return (
            False,
            out,
            f"Stream size too large: {size_mb:.2f} MB. Limit is {MAX_STREAM_SIZE_MB} MB."
        )

    if len(metadata["files"]) == 0:
        return False, out, "No files were fetched into OS stream"

    return True, out, err


def get_stream_files(stream_path: Path):
    """
    Return all real files inside stream.
    """

    validate_stream_path(stream_path)

    return [
        file
        for file in stream_path.rglob("*")
        if file.is_file()
    ]


def get_stream_file_metadata(stream_path: Path):
    """
    Return metadata for all files.
    """

    validate_stream_path(stream_path)

    files = []

    for file in get_stream_files(stream_path):
        try:
            files.append(
                {
                    "name": file.name,
                    "path": str(file),
                    "relative_path": str(file.relative_to(stream_path)),
                    "size_bytes": file.stat().st_size,
                    "extension": file.suffix.lower(),
                    "modified_time": file.stat().st_mtime
                }
            )
        except Exception:
            continue

    return files


def get_stream_size(stream_path: Path):
    """
    Total stream size in bytes.
    """

    validate_stream_path(stream_path)

    total = 0

    for file in get_stream_files(stream_path):
        try:
            total += file.stat().st_size
        except Exception:
            pass

    return total


def write_pipeline_metadata(stream_path: Path, metadata: dict):
    """
    Save pipeline metadata inside stream.
    """

    validate_stream_path(stream_path)

    metadata_path = stream_path / "gama_pipeline_metadata.json"

    with open(metadata_path, "w", encoding="utf-8") as file:
        json.dump(metadata, file, indent=4)


def read_pipeline_metadata(stream_path: Path):
    """
    Read pipeline metadata.
    """

    metadata_path = Path(stream_path) / "gama_pipeline_metadata.json"

    if not metadata_path.exists():
        return {}

    with open(metadata_path, "r", encoding="utf-8") as file:
        return json.load(file)


def detect_artifact_types(stream_path: Path):
    """
    Detect artifact categories.
    """

    validate_stream_path(stream_path)

    artifact_types = {
        "wheel": [],
        "zip": [],
        "exe": [],
        "msi": [],
        "tar": [],
        "json": [],
        "unknown": []
    }

    for file in get_stream_files(stream_path):
        suffix = file.suffix.lower()

        if suffix == ".whl":
            artifact_types["wheel"].append(file.name)
        elif suffix == ".zip":
            artifact_types["zip"].append(file.name)
        elif suffix == ".exe":
            artifact_types["exe"].append(file.name)
        elif suffix == ".msi":
            artifact_types["msi"].append(file.name)
        elif suffix in [".tar", ".gz", ".tgz"]:
            artifact_types["tar"].append(file.name)
        elif suffix == ".json":
            artifact_types["json"].append(file.name)
        else:
            artifact_types["unknown"].append(file.name)

    return artifact_types


def is_python_package_stream(stream_path: Path):
    """
    Check if stream contains Python installable wheels.
    """

    artifacts = detect_artifact_types(stream_path)

    return len(artifacts["wheel"]) > 0


def is_binary_stream(stream_path: Path):
    """
    Check if stream contains executable binaries.
    """

    artifacts = detect_artifact_types(stream_path)

    return len(artifacts["exe"]) > 0 or len(artifacts["msi"]) > 0


def cleanup_stream(stream_path: Path):
    """
    Safely delete OS stream.
    """

    if not stream_path:
        return False

    stream_path = Path(stream_path)

    temp_root = Path(tempfile.gettempdir()).resolve()
    resolved_stream = stream_path.resolve()

    if temp_root not in resolved_stream.parents:
        raise PipelineError(
            f"Unsafe cleanup blocked: {resolved_stream}"
        )

    if stream_path.exists():
        shutil.rmtree(stream_path, ignore_errors=True)
        return True

    return False


def safe_copy_to_stream(src: Path, stream_path: Path):
    """
    Safely copy file into stream.
    """

    validate_stream_path(stream_path)

    src = Path(src)

    if not src.exists():
        raise PipelineError("Source file does not exist")

    if not src.is_file():
        raise PipelineError("Source is not a file")

    dst = stream_path / src.name

    shutil.copy2(src, dst)

    return dst


def stream_health_check(stream_path: Path):
    """
    Final validation before Docker sandbox.
    """

    validate_stream_path(stream_path)

    files = get_stream_files(stream_path)
    size = get_stream_size(stream_path)
    artifacts = detect_artifact_types(stream_path)

    issues = []

    if not files:
        issues.append("No files found in stream")

    if size == 0:
        issues.append("Stream size is zero")

    if size > MAX_STREAM_SIZE_MB * 1024 * 1024:
        issues.append("Stream exceeds max allowed size")

    return {
        "healthy": len(issues) == 0,
        "issues": issues,
        "file_count": len(files),
        "total_size_bytes": size,
        "artifact_types": artifacts
    }
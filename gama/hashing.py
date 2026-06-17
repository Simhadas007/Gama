import hashlib
from pathlib import Path


def calculate_hashes(stream_path: Path):

    results = []

    for file in stream_path.iterdir():

        if not file.is_file():
            continue

        sha256 = hashlib.sha256()
        md5 = hashlib.md5()

        with open(file, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
                md5.update(chunk)

        results.append(
            {
                "file": file.name,
                "size": file.stat().st_size,
                "sha256": sha256.hexdigest(),
                "md5": md5.hexdigest()
            }
        )

    return results
import docker
from pathlib import Path


def get_client():
    return docker.from_env()


def run_in_sandbox(stream_path: Path):
    client = get_client()

    return client.containers.run(
        "python:3.12-slim",
        command="sleep 300",
        detach=True,
        network_disabled=True,
        mem_limit="512m",
        nano_cpus=500000000,
        read_only=False,
        security_opt=["no-new-privileges:true"],
        cap_drop=["ALL"]
    )


def copy_package_to_container(container, stream_path: Path):
    import tarfile
    import io

    tarstream = io.BytesIO()

    with tarfile.open(fileobj=tarstream, mode="w") as tar:
        for file in stream_path.iterdir():
            if file.is_file() and file.name != "gama_pipeline_metadata.json":
                tar.add(str(file), arcname=f"package/{file.name}")

    tarstream.seek(0)
    container.put_archive("/tmp", tarstream.read())
    return True


def execute_package_scan(container, target):
    wheel_cmd = "find /tmp/package -type f -name '*.whl'"
    wheel_result = container.exec_run(f"sh -c \"{wheel_cmd}\"")
    wheels = wheel_result.output.decode(errors="ignore").strip().splitlines()

    if wheels:
        install_cmd = (
            "python -m pip install "
            "--no-index "
            "--find-links=/tmp/package "
            f"{target}"
        )

        result = container.exec_run(f"sh -c \"{install_cmd}\"")

        return {
            "exit_code": result.exit_code,
            "output": f"Selected install command: {install_cmd}\n\n"
            + result.output.decode(errors="ignore")
        }

    archive_cmd = (
        "find /tmp/package -type f "
        "\\( -name '*.zip' -o -name '*.tar.gz' -o -name '*.tgz' \\)"
    )
    archive_result = container.exec_run(f"sh -c \"{archive_cmd}\"")
    archives = archive_result.output.decode(errors="ignore").strip().splitlines()

    if archives:
        archive = archives[0]
        scan_cmd = f"python -m zipfile -l {archive} | head -n 50"

        result = container.exec_run(f"sh -c \"{scan_cmd}\"")

        return {
            "exit_code": 0,
            "output": "Archive scan mode selected. No install attempted.\n"
            f"Archive: {archive}\n\n"
            + result.output.decode(errors="ignore")
        }

    return {
        "exit_code": 0,
        "output": "No installable Python artifact found. Static scan/report mode only."
    }


def stop_sandbox(container):
    try:
        container.stop(timeout=3)
    except Exception:
        pass
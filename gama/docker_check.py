import subprocess


def is_docker_installed():
    result = subprocess.run(
        ["docker", "--version"],
        capture_output=True,
        text=True
    )
    return result.returncode == 0


def is_docker_running():
    result = subprocess.run(
        ["docker", "ps"],
        capture_output=True,
        text=True
    )
    return result.returncode == 0


def install_docker_with_winget():
    result = subprocess.run(
        ["winget", "install", "-e", "--id", "Docker.DockerDesktop"],
        capture_output=True,
        text=True
    )

    return {
        "success": result.returncode == 0,
        "output": result.stdout,
        "error": result.stderr
    }
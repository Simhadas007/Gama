from pathlib import Path
from urllib.parse import urlparse
import subprocess
import requests
import shutil
import sys
import json
import platform


SOFTWARE_MAP = {
    "python": {
        "WINDOWS": "Python.Python.3",
        "MAC": "python",
        "LINUX": "python3"
    },
    "java": {
        "WINDOWS": "EclipseAdoptium.Temurin.21.JDK",
        "MAC": "openjdk",
        "LINUX": "openjdk-21-jdk"
    },
    "git": {
        "WINDOWS": "Git.Git",
        "MAC": "git",
        "LINUX": "git"
    },
    "node": {
        "WINDOWS": "OpenJS.NodeJS",
        "MAC": "node",
        "LINUX": "nodejs"
    },
    "docker": {
        "WINDOWS": "Docker.DockerDesktop",
        "MAC": "docker",
        "LINUX": "docker.io"
    },
    "vscode": {
        "WINDOWS": "Microsoft.VisualStudioCode",
        "MAC": "visual-studio-code",
        "LINUX": "code"
    },
    "chrome": {
        "WINDOWS": "Google.Chrome",
        "MAC": "google-chrome",
        "LINUX": "google-chrome-stable"
    },
    "firefox": {
        "WINDOWS": "Mozilla.Firefox",
        "MAC": "firefox",
        "LINUX": "firefox"
    },
    "7zip": {
        "WINDOWS": "7zip.7zip",
        "MAC": "p7zip",
        "LINUX": "p7zip-full"
    }
}


def get_os():
    system = platform.system().lower()

    if system == "windows":
        return "WINDOWS"

    if system == "darwin":
        return "MAC"

    if system == "linux":
        return "LINUX"

    return "UNKNOWN"


def detect_source(source: str, mode: str = "auto"):
    if mode != "auto":
        return mode.upper()

    source = source.strip()
    normalized = source.lower()
    parsed = urlparse(source)

    if parsed.scheme in ["http", "https"]:
        if "github.com" in parsed.netloc:
            return "GITHUB_URL"
        return "URL"

    if Path(source).exists():
        return "LOCAL_FILE"

    if "/" in source and not source.startswith("-"):
        return "GITHUB"

    if normalized.startswith("npm:"):
        return "NPM"

    os_type = get_os()

    if normalized in SOFTWARE_MAP:
        if os_type == "WINDOWS":
            return "WINDOWS_PACKAGE"
        if os_type == "MAC":
            return "BREW"
        if os_type == "LINUX":
            return "LINUX_PACKAGE"

    return "PYPI"


def fetch_to_stream(source: str, stream_path: Path, mode: str = "auto"):
    source_type = detect_source(source, mode)
    source_clean = source.strip()
    normalized = source_clean.lower()
    os_type = get_os()

    if source_type == "PYPI":
        return fetch_pypi(source_clean, stream_path)

    if source_type in ["URL", "GITHUB_URL"]:
        return fetch_url(source_clean, stream_path)

    if source_type == "LOCAL_FILE":
        return fetch_local(source_clean, stream_path)

    if source_type == "GITHUB":
        return fetch_github_repo(source_clean, stream_path)

    if source_type == "NPM":
        package = source_clean.replace("npm:", "", 1)
        return fetch_npm(package, stream_path)

    if source_type == "WINDOWS_PACKAGE":
        package = SOFTWARE_MAP[normalized]["WINDOWS"]
        return fetch_windows_package_metadata(package, stream_path)

    if source_type == "BREW":
        package = SOFTWARE_MAP[normalized]["MAC"]
        return fetch_brew_metadata(package, stream_path)

    if source_type == "LINUX_PACKAGE":
        package = SOFTWARE_MAP[normalized]["LINUX"]
        return fetch_linux_metadata(package, stream_path)

    if source_type == "WINGET":
        return fetch_winget_metadata(source_clean, stream_path)

    if source_type == "CHOCO":
        return fetch_choco_metadata(source_clean, stream_path)

    if source_type == "SCOOP":
        return fetch_scoop_metadata(source_clean, stream_path)

    if source_type == "BREW":
        return fetch_brew_metadata(source_clean, stream_path)

    if source_type == "APT":
        return fetch_apt_metadata(source_clean, stream_path)

    if source_type == "DNF":
        return fetch_dnf_metadata(source_clean, stream_path)

    if source_type == "PACMAN":
        return fetch_pacman_metadata(source_clean, stream_path)

    if source_type == "ZYPPER":
        return fetch_zypper_metadata(source_clean, stream_path)

    return False, "", f"Unsupported source type: {source_type}"


def fetch_pypi(package: str, stream_path: Path):
    cmd = [
        sys.executable,
        "-m",
        "pip",
        "download",
        package,
        "--only-binary=:all:",
        "--platform",
        "manylinux2014_x86_64",
        "--python-version",
        "312",
        "--implementation",
        "cp",
        "--abi",
        "cp312",
        "-d",
        str(stream_path)
    ]

    result = run_cmd(cmd, timeout=180)

    return result["success"], result["stdout"], result["stderr"]

def fetch_url(url: str, stream_path: Path):
    filename = Path(urlparse(url).path).name or "downloaded_file"
    output_path = stream_path / filename

    try:
        with requests.get(url, timeout=120, stream=True) as response:
            response.raise_for_status()

            with open(output_path, "wb") as file:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        file.write(chunk)

        return True, f"Downloaded URL: {url}", ""

    except Exception as e:
        return False, "", str(e)


def fetch_local(file_path: str, stream_path: Path):
    src = Path(file_path)

    if not src.exists():
        return False, "", "Local file not found"

    if not src.is_file():
        return False, "", "Local target is not a file"

    dst = stream_path / src.name
    shutil.copy2(src, dst)

    return True, f"Copied local file: {src}", ""


def fetch_github_repo(repo: str, stream_path: Path):
    if repo.startswith("http"):
        url = repo
    else:
        url = f"https://github.com/{repo}/archive/refs/heads/main.zip"

    return fetch_url(url, stream_path)


def fetch_npm(package: str, stream_path: Path):
    if not command_exists("npm"):
        return False, "", "npm is not installed"

    cmd = ["npm", "pack", package]
    result = run_cmd(cmd, cwd=stream_path, timeout=180)

    return result["success"], result["stdout"], result["stderr"]


def fetch_windows_package_metadata(package: str, stream_path: Path):
    if command_exists("winget"):
        return fetch_winget_metadata(package, stream_path)

    if command_exists("choco"):
        return fetch_choco_metadata(package, stream_path)

    if command_exists("scoop"):
        return fetch_scoop_metadata(package, stream_path)

    return False, "", "No Windows package manager found: winget/choco/scoop unavailable"


def fetch_winget_metadata(package: str, stream_path: Path):
    if not command_exists("winget"):
        return False, "", "winget is not installed"

    cmd = [
        "winget",
        "show",
        "--id",
        package,
        "--accept-source-agreements"
    ]

    result = run_cmd(cmd, timeout=20)

    if not result["success"]:
        metadata = {
            "source": "winget",
            "package": package,
            "status": "metadata_timeout_or_failed",
            "message": "Winget metadata lookup failed or timed out. Static metadata created.",
            "command": result["command"],
            "stdout": result["stdout"],
            "stderr": result["stderr"],
            "returncode": result["returncode"],
        }

        output_file = stream_path / f"winget_{safe_name(package)}_metadata.json"

        with open(output_file, "w", encoding="utf-8") as file:
            json.dump(metadata, file, indent=4)

        return True, "Winget metadata fallback created.", ""

    return save_metadata(
        stream_path=stream_path,
        manager="winget",
        package=package,
        result=result
    )

def fetch_choco_metadata(package: str, stream_path: Path):
    if not command_exists("choco"):
        return False, "", "Chocolatey is not installed"

    cmd = ["choco", "info", package]
    result = run_cmd(cmd, timeout=90)

    return save_metadata(
        stream_path=stream_path,
        manager="chocolatey",
        package=package,
        result=result
    )


def fetch_scoop_metadata(package: str, stream_path: Path):
    if not command_exists("scoop"):
        return False, "", "Scoop is not installed"

    cmd = ["scoop", "info", package]
    result = run_cmd(cmd, timeout=90)

    return save_metadata(
        stream_path=stream_path,
        manager="scoop",
        package=package,
        result=result
    )


def fetch_brew_metadata(package: str, stream_path: Path):
    if not command_exists("brew"):
        return False, "", "Homebrew is not installed"

    cmd = ["brew", "info", "--json=v2", package]
    result = run_cmd(cmd, timeout=90)

    return save_metadata(
        stream_path=stream_path,
        manager="homebrew",
        package=package,
        result=result
    )


def fetch_linux_metadata(package: str, stream_path: Path):
    if command_exists("apt-cache"):
        return fetch_apt_metadata(package, stream_path)

    if command_exists("dnf"):
        return fetch_dnf_metadata(package, stream_path)

    if command_exists("pacman"):
        return fetch_pacman_metadata(package, stream_path)

    if command_exists("zypper"):
        return fetch_zypper_metadata(package, stream_path)

    return False, "", "No supported Linux package manager found: apt/dnf/pacman/zypper unavailable"


def fetch_apt_metadata(package: str, stream_path: Path):
    if not command_exists("apt-cache"):
        return False, "", "apt-cache is not installed"

    cmd = ["apt-cache", "show", package]
    result = run_cmd(cmd, timeout=90)

    return save_metadata(
        stream_path=stream_path,
        manager="apt",
        package=package,
        result=result
    )


def fetch_dnf_metadata(package: str, stream_path: Path):
    if not command_exists("dnf"):
        return False, "", "dnf is not installed"

    cmd = ["dnf", "info", package]
    result = run_cmd(cmd, timeout=90)

    return save_metadata(
        stream_path=stream_path,
        manager="dnf",
        package=package,
        result=result
    )


def fetch_pacman_metadata(package: str, stream_path: Path):
    if not command_exists("pacman"):
        return False, "", "pacman is not installed"

    cmd = ["pacman", "-Si", package]
    result = run_cmd(cmd, timeout=90)

    return save_metadata(
        stream_path=stream_path,
        manager="pacman",
        package=package,
        result=result
    )


def fetch_zypper_metadata(package: str, stream_path: Path):
    if not command_exists("zypper"):
        return False, "", "zypper is not installed"

    cmd = ["zypper", "info", package]
    result = run_cmd(cmd, timeout=90)

    return save_metadata(
        stream_path=stream_path,
        manager="zypper",
        package=package,
        result=result
    )


def save_metadata(stream_path: Path, manager: str, package: str, result: dict):
    metadata = {
        "os": get_os(),
        "source": manager,
        "package": package,
        "command": result["command"],
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "returncode": result["returncode"],
        "success": result["success"]
    }

    output_file = stream_path / f"{manager}_{safe_name(package)}_metadata.json"

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(metadata, file, indent=4)

    return result["success"], result["stdout"], result["stderr"]


def run_cmd(cmd, cwd=None, timeout=30):
    try:
        result = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        return {
            "command": cmd,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0
        }

    except subprocess.TimeoutExpired:
        return {
            "command": cmd,
            "returncode": 124,
            "stdout": "",
            "stderr": f"Command timed out after {timeout} seconds",
            "success": False
        }

    except Exception as e:
        return {
            "command": cmd,
            "returncode": 1,
            "stdout": "",
            "stderr": str(e),
            "success": False
        }


def command_exists(command: str):
    return shutil.which(command) is not None


def safe_name(name: str):
    return (
        name.replace("/", "_")
        .replace("\\", "_")
        .replace(":", "_")
        .replace(" ", "_")
        .replace(".", "_")
    )
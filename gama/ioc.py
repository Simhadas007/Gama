import re
import zipfile
from pathlib import Path


URL_REGEX = r"https?://[^\s'\"<>]+"
IP_REGEX = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
EMAIL_REGEX = r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b"
DOMAIN_REGEX = r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|in|dev|xyz|ru|cn|info)\b"
BASE64_REGEX = r"\b[A-Za-z0-9+/]{40,}={0,2}\b"


def extract_iocs_from_text(text: str):
    return {
        "urls": sorted(set(re.findall(URL_REGEX, text))),
        "ips": sorted(set(re.findall(IP_REGEX, text))),
        "emails": sorted(set(re.findall(EMAIL_REGEX, text))),
        "domains": sorted(set(re.findall(DOMAIN_REGEX, text))),
        "base64_strings": sorted(set(re.findall(BASE64_REGEX, text)))[:20],
    }


def extract_iocs(stream_path: Path):
    combined_text = ""

    for file in stream_path.iterdir():
        if file.suffix == ".whl":
            try:
                with zipfile.ZipFile(file, "r") as zip_ref:
                    for name in zip_ref.namelist():
                        if name.endswith((".py", ".txt", ".cfg", ".toml", ".json")):
                            combined_text += zip_ref.read(name).decode(errors="ignore") + "\n"
            except Exception:
                pass

    return extract_iocs_from_text(combined_text)
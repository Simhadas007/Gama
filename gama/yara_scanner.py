import yara
import tempfile
from pathlib import Path


RULES = r"""
rule Suspicious_Commands
{
    strings:
        $a = "powershell"
        $b = "cmd.exe"
        $c = "os.system"
        $d = "subprocess"
        $e = "eval("
        $f = "exec("

    condition:
        any of them
}

rule Network_Activity
{
    strings:
        $a = "socket"
        $b = "requests.get"
        $c = "requests.post"
        $d = "urllib"

    condition:
        any of them
}
"""


def yara_scan_text(content: str):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
        f.write(content.encode(errors="ignore"))
        temp_file = f.name

    rules = yara.compile(source=RULES)
    matches = rules.match(temp_file)

    return [m.rule for m in matches]
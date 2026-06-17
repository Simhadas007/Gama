import typer
from rich.console import Console
from rich.prompt import Confirm
from gama.docker_check import (
    is_docker_installed,
    is_docker_running,
    install_docker_with_winget
)

from gama.pipeline import create_os_stream, fetch_package, cleanup_stream
from gama.docker_runner import (
    run_in_sandbox,
    copy_package_to_container,
    execute_package_scan,
    stop_sandbox
)
from gama.risk import calculate_risk
from gama.installer import install_on_host
from gama.evidence import collect_evidence, summarize_evidence
from gama.static_scan import scan_package_files
from gama.reporter import save_report
from gama.pdf_reporter import save_pdf_report
from gama.monitor import (
    capture_before_state,
    capture_after_state,
    analyze_behavior
)
from gama.hashing import calculate_hashes
from gama.ioc import extract_iocs
from gama.mitre_mapper import map_to_mitre
from gama.history import get_reports, get_latest_report, read_report, clean_reports

VERSION = "1.0.0"

app = typer.Typer(add_completion=False)
console = Console()


@app.callback(invoke_without_command=True)
def main(
    target: str = typer.Argument(None),
    history: bool = typer.Option(False, "--history", help="Show scan history"),
    report: str = typer.Option(None, "--report", help="Show report by name or latest"),
    clean: bool = typer.Option(False, "--clean", help="Delete all scan reports"),
    version: bool = typer.Option(False, "--version", help="Show version"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show full technical output")
):
    if version:
        console.print(f"Gama Zero-Trust Scanner v{VERSION}")
        return

    if history:
        reports = get_reports()
        if not reports:
            console.print("[yellow]No scan history found.[/yellow]")
            return

        console.print("[bold cyan]Scan History[/bold cyan]")
        for item in reports:
            console.print(f" - {item.name}")
        return

    if clean:
        count = clean_reports()
        console.print(f"[green]Deleted {count} report files.[/green]")
        return

    if report:
        show_report(report)
        return

    if not target:
        console.print("[red]Target required.[/red]")
        console.print("Example: gama requests")
        console.print("Use: gama --help")
        return

    run_scan(target, verbose)


def show_report(report):
    if report == "latest":
        report_path = get_latest_report()
    else:
        matches = [
            item for item in get_reports()
            if report.lower() in item.name.lower()
        ]
        report_path = matches[0] if matches else None

    if not report_path:
        console.print("[red]Report not found.[/red]")
        return

    data = read_report(report_path)

    console.print(f"[bold cyan]Report:[/bold cyan] {report_path.name}")
    console.print(f"Package: {data.get('package')}")
    console.print(f"Scan Time: {data.get('scan_time')}")
    console.print(f"Risk Score: {data.get('risk', {}).get('score')}/100")
    console.print(f"Verdict: {data.get('risk', {}).get('verdict')}")
    console.print(f"MITRE Hits: {len(data.get('mitre_attack', []))}")
    console.print(f"IOC Categories: {len(data.get('iocs', {}))}")


def count_iocs(ioc_results):
    return sum(len(values) for values in ioc_results.values())


def print_step(name, status="OK"):
    if status == "OK":
        console.print(f"[green][✓][/green] {name}")
    elif status == "WARN":
        console.print(f"[yellow][!][/yellow] {name}")
    else:
        console.print(f"[red][x][/red] {name}")


def run_scan(package: str, verbose: bool = False):
    console.print("\n[bold cyan]Gama Zero-Trust Installer[/bold cyan]")
    console.print(f"Target : [yellow]{package}[/yellow]\n")

    stream_path = None
    container = None
    docker_available = False

    try:
        stream_path = create_os_stream()

        ok, out, err = fetch_package(package, stream_path)

        if not ok:
            print_step("Fetch failed", "FAIL")
            console.print(f"[red]{err}[/red]")
            return

        downloaded_files = [
            file.name for file in stream_path.iterdir()
            if file.is_file()
        ]

        print_step("Package captured in OS stream")
        console.print("[dim]Not installed on host yet.[/dim]")

        hash_results = calculate_hashes(stream_path)
        print_step("File hash analysis completed")

        ioc_results = extract_iocs(stream_path)
        ioc_total = count_iocs(ioc_results)
        print_step("IOC extraction completed")

        static_findings = scan_package_files(stream_path)
        print_step("Static package scan completed")

        behavior_findings = []
        evidence_summary = []
        docker_available = False

        if not is_docker_installed():

            print_step("Docker not installed", "WARN")

            answer = console.input(
                "\nDocker is required for advanced sandbox analysis.\n"
                "Install Docker Desktop now? [Yes/No]: "
            ).strip().lower()

            if answer in ["yes", "y"]:

                result = install_docker_with_winget()

                if result["success"]:
                    console.print(
                        "[green]Docker Desktop installation started.[/green]"
                    )
                    console.print(
                        "[yellow]Please open Docker Desktop and rerun Gama after installation.[/yellow]"
                    )
                else:
                    console.print("[red]Docker installation failed.[/red]")

                    if verbose:
                        console.print(result["error"])

            console.print(
               "[yellow]Running Static Analysis Mode.[/yellow]"
            )

            scan_result = {
                "exit_code": 0,
                "output": "Docker not installed. Dynamic analysis skipped."
            }

        elif not is_docker_running():

            print_step("Docker installed but not running", "WARN")

            console.print(
                "[yellow]Docker Desktop is not running.[/yellow]"
            )

            console.print(
                "[yellow]Start Docker Desktop for best scan performance.[/yellow]"
            )

            console.print(
                "[yellow]Running Static Analysis Mode.[/yellow]"
            )

            scan_result = {
                "exit_code": 0,
                "output": "Docker not running. Dynamic analysis skipped."
            }

        else:

            docker_available = True

            container = run_in_sandbox(stream_path)

            print_step("Docker sandbox started")

            copy_package_to_container(container, stream_path)

            print_step("Package transferred to sandbox")

            before_state = capture_before_state(container)

            scan_result = execute_package_scan(container, package)

            after_state = capture_after_state(container)

            behavior_findings = analyze_behavior(
                before_state,
                after_state
            )

            if scan_result["exit_code"] == 0:
                print_step("Sandbox execution completed")
            else:
                print_step("Sandbox execution failed", "WARN")

            evidence = collect_evidence(container)

            evidence_summary = summarize_evidence(evidence)

            print_step("Sandbox evidence collected")

        combined_evidence = (
            scan_result["output"]
            + "\n"
            + "\n".join(evidence_summary)
            + "\n"
            + "\n".join(behavior_findings)
        )

        mitre_findings = map_to_mitre(combined_evidence)
        risk = calculate_risk(combined_evidence)

        report_path = save_report(
            package=package,
            downloaded_files=downloaded_files,
            static_findings=static_findings,
            evidence_summary=evidence_summary + behavior_findings,
            risk=risk,
            hash_results=hash_results,
            ioc_results=ioc_results,
            mitre_findings=mitre_findings
        )

        pdf_path = save_pdf_report(
            package=package,
            risk=risk,
            hash_results=hash_results,
            ioc_results=ioc_results,
            mitre_findings=mitre_findings
        )

        console.print("\n[bold]Risk Summary[/bold]")
        console.print(f"Risk Score : [yellow]{risk['score']}/100[/yellow]")
        console.print(f"Verdict    : [bold]{risk['verdict']}[/bold]")
        console.print(f"Files      : {len(downloaded_files)}")
        console.print(f"IOC Hits   : {ioc_total}")
        console.print(f"MITRE Hits : {len(mitre_findings)}")
        console.print(f"Findings   : {len(risk['findings'])}")
        if docker_available:
            console.print("Dynamic Analysis : Enabled")
        else:
            console.print("Dynamic Analysis : Skipped")

        console.print("\n[bold]Reports[/bold]")
        console.print(f"JSON : {report_path}")
        console.print(f"PDF  : {pdf_path}")

        if verbose:
            print_verbose_output(
                downloaded_files,
                hash_results,
                ioc_results,
                static_findings,
                scan_result,
                behavior_findings,
                evidence_summary,
                mitre_findings,
                risk
            )

        if scan_result["exit_code"] != 0:
            console.print(
                "\n[yellow]Sandbox execution failed. Static analysis and reports were completed.[/yellow]"
            )

        if risk["score"] >= 85:
            console.print("[red]Critical risk target. Host installation blocked.[/red]")
            return

        if risk["score"] >= 45:
            console.print("[yellow]Warning: Medium risk indicators detected.[/yellow]")

        while True:
            answer = console.input(
                "\nInstall this package on host system? [Yes/No]: "
            ).strip().lower()

            if answer in ["yes", "y"]:
                allow = True
                break

            if answer in ["no", "n"]:
                allow = False
                break

            console.print("[red]Please enter Yes or No[/red]")
        if not allow:
            console.print("[yellow]User rejected installation. Package not installed.[/yellow]")
            return

        console.print("[blue]Installing package on host system...[/blue]")
        install_result = install_on_host(package)

        if install_result["success"]:
            console.print("[green]Package installed successfully on host.[/green]")
        else:
            console.print("[red]Host installation failed.[/red]")
            if verbose:
                console.print(install_result["error"])

    except Exception as e:
        console.print("[red]Error occurred:[/red]")
        console.print(str(e))

    finally:
        if container:
            stop_sandbox(container)

        if stream_path:
            cleanup_stream(stream_path)
            if verbose:
                console.print("[yellow]OS stream cleaned.[/yellow]")


def print_verbose_output(
    downloaded_files,
    hash_results,
    ioc_results,
    static_findings,
    scan_result,
    behavior_findings,
    evidence_summary,
    mitre_findings,
    risk
):
    console.print("\n[bold blue]Verbose Technical Details[/bold blue]")

    console.print("\n[bold]Downloaded Files[/bold]")
    for file_name in downloaded_files:
        console.print(f" - {file_name}")

    console.print("\n[bold]Hashes[/bold]")
    for item in hash_results:
        console.print(f" - {item['file']}")
        console.print(f"   SHA256: {item['sha256']}")
        console.print(f"   MD5   : {item['md5']}")

    console.print("\n[bold]IOCs[/bold]")
    for category, values in ioc_results.items():
        if values:
            console.print(f"{category}:")
            for value in values[:10]:
                console.print(f" - {value}")

    console.print("\n[bold]Static Findings[/bold]")
    if static_findings:
        for finding in static_findings[:50]:
            console.print(f" - {finding}")
    else:
        console.print("No static findings.")

    console.print("\n[bold]Sandbox Output[/bold]")
    console.print(scan_result["output"][:3000])

    console.print("\n[bold]Behavior Findings[/bold]")
    if behavior_findings:
        for finding in behavior_findings:
            console.print(f" - {finding}")
    else:
        console.print("No behavior findings.")

    console.print("\n[bold]Evidence Summary[/bold]")
    if evidence_summary:
        for item in evidence_summary:
            console.print(f" - {item}")
    else:
        console.print("No notable evidence.")

    console.print("\n[bold]MITRE ATT&CK[/bold]")
    if mitre_findings:
        for finding in mitre_findings:
            console.print(
                f" - {finding['technique_id']} | "
                f"{finding['technique']} | "
                f"{finding['tactic']} | "
                f"{finding['severity']}"
            )
    else:
        console.print("No MITRE mappings.")

    console.print("\n[bold]Risk Findings[/bold]")
    if risk["findings"]:
        for finding in risk["findings"]:
            console.print(f" - {finding}")
    else:
        console.print("No risk findings.")
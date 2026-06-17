def execute_package_scan(container, target):
    try:

        files_cmd = (
            "find /tmp/package "
            "-type f "
            "\\( -name '*.whl' "
            "-o -name '*.zip' "
            "-o -name '*.tar.gz' "
            "\\)"
        )

        result = container.exec_run(files_cmd)

        files = (
            result.output.decode(errors="ignore")
            .strip()
            .splitlines()
        )

        if files:

            package_file = files[0]

            install_cmd = (
                f"python -m pip install "
                f"--no-index "
                f"{package_file}"
            )

        else:

            install_cmd = (
                f"python -m pip install "
                f"--no-index "
                f"--find-links=/tmp/package "
                f"{target}"
            )

        result = container.exec_run(install_cmd)

        return {
            "exit_code": result.exit_code,
            "output": result.output.decode(errors="ignore")
        }

    except Exception as e:
        return {
            "exit_code": 1,
            "output": str(e)
        }
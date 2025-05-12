#!/usr/bin/python

import os
import sys
import subprocess
from pathlib import Path

def main() -> None:
    args: list[str] = []
    for arg in sys.argv[1:]:
        if not arg.startswith("-") and arg.endswith(".s") and ".abisan." not in arg:
            subprocess.run(
                ["python3", "instrument.py", arg], check=True
            )
            args.append(arg + ".abisan.s")

            subprocess.run(
                ["rm", arg + ".abisan.intermediate.s", arg + ".abisan.intermediate.s.o"], check=True
            )

    # Directory this file is found in
    this_directory: Path = Path(__file__).resolve().parent

    # Remove current directory from the path
    new_path: list[str] = []
    path: str | None = os.environ.get("PATH", None)
    if path is not None:
        for path_element in path.split(":"):
            if Path(path_element).resolve() != this_directory:
                new_path.append(path_element)

    subproc_env: dict[str, str] = os.environ.copy()
    if path is not None:
        subproc_env["PATH"] = ":".join(new_path)

    try:
        subprocess.run(
            ["as", *args], check=True, env=subproc_env
        )
    except subprocess.CalledProcessError:
        subprocess.run(
            ["llvm-as", *args], check=True, env=subproc_env
        )

if __name__ == "__main__":
    main()

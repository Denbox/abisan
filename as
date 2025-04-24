#!/usr/bin/python

import os
import sys
import subprocess
from pathlib import Path


REAL_AS: str = "/usr/bin/as"
INSTRUMENTED_SUFFIX: str = ".abisan.s"

def main() -> None:
    args: list[str] = sys.argv[1:]

    # for now, assume that the user has set their ABISAN_TUNABLES_SYNTAX environment variable correctly
    # TODO: detect whether file is att or intel and set env accordingly

    for i in range(len(args)):
        arg: str = args[i]
        
        if not arg.startswith("-") and arg.endswith(".s") and not ".abisan." in arg:
            
            subprocess.run(
                ["python3", "instrument.py", arg], check=True 
            )
            args[i] = arg + INSTRUMENTED_SUFFIX

            subprocess.run(
                ["rm", arg + ".abisan.intermediate.s"], check=True
            )
            subprocess.run(
                ["rm", arg + ".abisan.intermediate.s.o"], check=True
            )


    # Converts a string representing a path to an absolute path
    def path_to_absolute(path: str) -> str:
        p: Path = Path(path)

        if not p.is_absolute():
            p = p.resolve()

        return str(p)

    
    # Getting list of paths
    paths: list[str] = list(map(path_to_absolute,os.environ.get("PATH").split(":")))
    # Directory this file is found in
    this_directory: str = path_to_absolute(__file__).rsplit("/",maxsplit=1)[0]

    # Remove current directory from the path
    for path in paths:
        if this_directory in path:
            paths.remove(path)

    subproc_env = os.environ.copy()
    subproc_env["PATH"] = ":".join(paths)

    subprocess.run(
        [REAL_AS] + args, check=True, env=subproc_env
    )
    
if __name__ == "__main__":
    main()

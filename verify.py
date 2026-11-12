"""Усі обов'язкові перевірки; зберігає фактичний stdout/stderr у results/."""
from pathlib import Path
import subprocess
import sys


def main():
    project = Path(__file__).resolve().parent
    results = project / "results"
    results.mkdir(exist_ok=True)
    for name, arguments in (
        ("tests", ["-m", "unittest", "-v"]),
        ("attacks", ["demo.py", "attacks"]),
        ("fork", ["demo.py", "fork"]),
        ("experiment", ["experiment.py"]),
    ):
        print(f"RUN: python {' '.join(arguments)}", flush=True)
        process = subprocess.run([sys.executable, "-X", "utf8", *arguments], cwd=project,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 encoding="utf-8", errors="replace")
        (results / f"{name}.txt").write_text(process.stdout, encoding="utf-8")
        print(process.stdout, end="", flush=True)
        if process.returncode:
            raise SystemExit(process.returncode)
    print("PASS: all checks completed; logs saved in results/", flush=True)


if __name__ == "__main__":
    main()

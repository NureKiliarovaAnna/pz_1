"""Реальний PoW: незалежні заголовки, perf_counter, CSV та PNG без GUI."""
import argparse
import csv
import platform
from pathlib import Path
import statistics
import time

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from blockchain import canonical, genesis, mine_header, sha


def experiment(runs=10, output="results"):
    if runs < 10:
        raise ValueError("At least 10 measurements per difficulty are required")
    directory = Path(output)
    directory.mkdir(parents=True, exist_ok=True)
    rows, summary = [], []
    for difficulty in (1, 2, 3, 4):
        times, attempts = [], []
        for trial in range(1, runs + 1):
            header = dict(genesis()["header"])
            header.update(index=1, difficulty=difficulty,
                          timestamp=time.time_ns() // 1_000_000,
                          merkle_root=sha(canonical({"difficulty": difficulty, "trial": trial,
                                                     "salt": time.time_ns()})))
            start = time.perf_counter()
            mined, digest = mine_header(header)
            seconds = time.perf_counter() - start
            assert digest.startswith("0" * difficulty)
            times.append(seconds)
            attempts.append(mined["nonce"] + 1)
            rows.append({"difficulty": difficulty, "trial": trial, "seconds": seconds,
                         "attempts": mined["nonce"] + 1, "hash": digest})
            print(f"d={difficulty} trial={trial:02d}/{runs} seconds={seconds:.6f} "
                  f"attempts={mined['nonce'] + 1}", flush=True)
        summary.append({"difficulty": difficulty, "runs": runs,
                        "mean_seconds": statistics.mean(times),
                        "stdev_seconds": statistics.stdev(times),
                        "min_seconds": min(times), "max_seconds": max(times),
                        "median_seconds": statistics.median(times),
                        "mean_attempts": statistics.mean(attempts), "expected_attempts": 16 ** difficulty})
    for filename, records in (("measurements.csv", rows), ("statistics.csv", summary)):
        with (directory / filename).open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(records[0]))
            writer.writeheader()
            writer.writerows(records)
    fig, axis = plt.subplots(figsize=(9, 5))
    means = [r["mean_seconds"] for r in summary]
    # min/max асиметричні і завжди додатні, тому коректні на логарифмічній осі.
    axis.errorbar([1, 2, 3, 4], means,
                  yerr=[[r["mean_seconds"] - r["min_seconds"] for r in summary],
                        [r["max_seconds"] - r["mean_seconds"] for r in summary]],
                  fmt="o-", capsize=6, label=f"Mean and min–max ({runs} runs)")
    for difficulty in (1, 2, 3, 4):
        axis.scatter([difficulty] * runs, [r["seconds"] for r in rows if r["difficulty"] == difficulty],
                     alpha=0.4, s=18)
    baseline = means[0]
    axis.plot([1, 2, 3, 4], [baseline * 16 ** i for i in range(4)], "--", label="16× per extra hex zero")
    axis.set(yscale="log", xticks=[1, 2, 3, 4], xlabel="Difficulty (leading hexadecimal zeros)",
             ylabel="Mining time (seconds, log scale)", title="SHA-256 Proof of Work")
    axis.grid(True, which="both", alpha=0.25)
    axis.legend()
    fig.tight_layout()
    fig.savefig(directory / "mining_time.png", dpi=180)
    plt.close(fig)
    (directory / "environment.txt").write_text(
        f"UTC run time: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())}\n"
        f"Python: {platform.python_version()}\nPlatform: {platform.platform()}\n"
        "Timer: time.perf_counter; one process; no parallel mining\n"
        "Error bars: observed min/max; stdev is in statistics.csv\n", encoding="utf-8")
    print("Saved measurements.csv, statistics.csv, mining_time.png, environment.txt", flush=True)
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--output", default="results")
    args = parser.parse_args()
    experiment(args.runs, args.output)

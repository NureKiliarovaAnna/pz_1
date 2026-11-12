"""Запуск трьох окремих процесів; Ctrl+C завершує лише власні процеси."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import time

import requests


class Network:
    def __init__(self, directory, ports=(8001, 8002, 8003), sync_interval=0):
        self.directory = Path(directory)
        self.ports, self.sync_interval = ports, sync_interval
        self.urls = [f"http://127.0.0.1:{port}" for port in ports]
        self.processes, self.logs = [], []

    def __enter__(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        try:
            for port, url in zip(self.ports, self.urls):
                # Не підключаємо демонстрацію до випадково запущеного старого вузла.
                import socket
                with socket.socket() as probe:
                    probe.bind(("127.0.0.1", port))
                log = (self.directory / f"node_{port}.log").open("w", encoding="utf-8")
                self.logs.append(log)
                command = [sys.executable, str(Path(__file__).with_name("node.py")),
                           "--port", str(port), "--data", str((self.directory / f"node_{port}.json").resolve()),
                           "--sync-interval", str(self.sync_interval), "--managed", "--peers"]
                command.extend(peer for peer in self.urls if peer != url)
                flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                self.processes.append(subprocess.Popen(command, stdin=subprocess.PIPE,
                                                       stdout=log, stderr=log, creationflags=flags))
            deadline = time.monotonic() + 25
            for process, url in zip(self.processes, self.urls):
                while True:
                    if process.poll() is not None:
                        raise RuntimeError(f"Node {url} exited; inspect logs in {self.directory}")
                    try:
                        response = requests.get(url + "/status", timeout=0.3)
                        response.raise_for_status()
                        break
                    except requests.RequestException:
                        if time.monotonic() > deadline:
                            raise RuntimeError(f"Node startup timed out: {url}")
                        time.sleep(0.1)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *args):
        for process in self.processes:
            if process.stdin:
                process.stdin.close()
        for process in self.processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for log in self.logs:
            log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", default="data")
    parser.add_argument("--ports", nargs=3, type=int, default=[8001, 8002, 8003])
    args = parser.parse_args()
    try:
        with Network(args.data, args.ports, sync_interval=3) as network:
            print("Three nodes ready: " + ", ".join(network.urls), flush=True)
            print("Ctrl+C stops all three nodes.", flush=True)
            while True:
                if any(p.poll() is not None for p in network.processes):
                    raise RuntimeError("A node stopped unexpectedly")
                time.sleep(0.5)
    except KeyboardInterrupt:
        print("Nodes stopped.")


if __name__ == "__main__":
    main()

"""Зберігає лише заголовки: PoW, посилання, складність і докази включення."""
import argparse
import json
from pathlib import Path

import requests

from blockchain import chain_work, validate_headers, verify_proof


class LightClient:
    def __init__(self, headers, rules=None):
        if rules is None:
            validate_headers(headers)
        else:
            validate_headers(headers, rules)
        self.headers = headers

    def contains(self, height, identifier, proof):
        return (0 <= height < len(self.headers)
                and verify_proof(identifier, proof, self.headers[height]["header"]["merkle_root"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("height", type=int)
    parser.add_argument("txid")
    parser.add_argument("--node", default="http://127.0.0.1:8001")
    parser.add_argument("--output", default="data/light_headers.json")
    args = parser.parse_args()
    response = requests.get(args.node + "/headers", timeout=15)
    response.raise_for_status()
    client = LightClient(response.json()["headers"])
    response = requests.get(f"{args.node}/proof/{args.height}/{args.txid}", timeout=15)
    response.raise_for_status()
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(client.headers, indent=2), encoding="utf-8")
    result = client.contains(args.height, args.txid, response.json()["proof"])
    print(json.dumps({"included": result, "headers": len(client.headers),
                      "work": chain_work(client.headers)}, indent=2))
    if not result:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

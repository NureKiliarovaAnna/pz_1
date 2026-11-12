"""Клієнт: приватний ключ ніколи не надсилається вузлу."""
import argparse
import json
from pathlib import Path

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from blockchain import address, canonical


def public_hex(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def sign_transaction(key, recipient, amount, fee, nonce):
    public = public_hex(key)
    tx = {"type": "transfer", "sender": address(public), "recipient": recipient,
          "amount": amount, "fee": fee, "nonce": nonce, "public_key": public}
    tx["signature"] = key.sign(canonical(tx)).hex()
    return tx


def key_path(name):
    if not name or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in name):
        raise ValueError("Wallet name: letters, digits, underscore or dash only")
    return Path.home() / ".blockchain_pz1_wallets" / (name + ".pem")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", default="http://127.0.0.1:8001")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("create", "show", "send"):
        p = sub.add_parser(command)
        p.add_argument("name")
        if command == "send":
            p.add_argument("recipient")
            p.add_argument("amount", type=int)
            p.add_argument("--fee", type=int, default=1)
    args = parser.parse_args()
    path = key_path(args.name)
    project = Path(__file__).resolve().parent
    if path.resolve().is_relative_to(project):
        raise ValueError("Private keys must be stored outside the project")
    if args.command == "create":
        key = Ed25519PrivateKey.generate()
        path.parent.mkdir(parents=True, exist_ok=True)
        # Режим x захищає від випадкового перезапису наявного гаманця.
        with path.open("xb") as stream:
            stream.write(key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
        response = requests.post(args.node + "/wallets", json={"public_key": public_hex(key)}, timeout=10)
    else:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        info = {"address": address(public_hex(key)), "public_key": public_hex(key)}
        if args.command == "show":
            print(json.dumps(info, indent=2))
            return
        state = requests.get(args.node + "/balance/" + info["address"], timeout=10)
        state.raise_for_status()
        tx = sign_transaction(key, args.recipient, args.amount, args.fee, state.json()["next_nonce"])
        response = requests.post(args.node + "/transactions", json=tx, timeout=10)
    print(json.dumps(response.json(), indent=2))
    response.raise_for_status()


if __name__ == "__main__":
    main()

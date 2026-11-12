"""Відтворювані демонстрації, завжди з чистими тимчасовими даними."""
import argparse
import copy
import json
from pathlib import Path
import tempfile

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from blockchain import (Blockchain, Invalid, address, mine_header,
                        txid, validate_chain)
from run_network import Network
from wallet import public_hex, sign_transaction


def wallet():
    key = Ed25519PrivateKey.generate()
    return key, address(public_hex(key))


def rejected(label, action, fragment):
    try:
        action()
    except Invalid as error:
        reason = str(error)
        assert fragment in reason, (fragment, reason)
        print(f"{label}\n  REJECTED: {reason}", flush=True)
    else:
        raise AssertionError("Attack unexpectedly accepted: " + label)


def attacks():
    with tempfile.TemporaryDirectory(prefix="blockchain_attacks_") as temporary:
        chain = Blockchain(Path(temporary) / "chain.json")
        alice, alice_addr = wallet()
        _, bob_addr = wallet()
        chain.mine(alice_addr)
        tx = sign_transaction(alice, bob_addr, 10, 1, 1)
        chain.add_transaction(tx)
        chain.mine(alice_addr)
        chain.mine(alice_addr)
        validate_chain(chain.chain)

        changed = copy.deepcopy(chain.chain)
        changed[2]["transactions"][1]["amount"] += 1
        rejected("1. Change amount in an old transaction",
                 lambda: validate_chain(changed), "Merkle root mismatch")

        changed = copy.deepcopy(chain.chain)
        old_hash = changed[2]["hash"]
        # Мітка часу — дані блока, які можна змінити без підробки підпису.
        changed[2]["header"]["timestamp"] += 1
        changed[2]["header"], changed[2]["hash"] = mine_header(changed[2]["header"])
        print("2. Re-mine changed block 2; leave block 3 untouched")
        print(f"  old hash={old_hash}\n  new hash={changed[2]['hash']}")
        print(f"  block 3 previous_hash={changed[3]['header']['previous_hash']}")
        print(f"  new PoW valid={changed[2]['hash'].startswith('00')}")
        rejected("  Check following link", lambda: validate_chain(changed), "broken previous_hash link")

        fake = sign_transaction(alice, bob_addr, 1, 0, 2)
        fake["signature"] = "00" * 64
        rejected("3. Forged signature", lambda: chain.add_transaction(fake), "invalid Ed25519 signature")

        balance = chain.account(alice_addr)["balance"]
        first = sign_transaction(alice, bob_addr, balance, 0, 2)
        second = sign_transaction(alice, bob_addr, balance, 0, 3)
        chain.add_transaction(first)
        rejected("4. Double spend: both transactions spend the full balance",
                 lambda: chain.add_transaction(second), "insufficient available balance")
        rejected("5. Replay an already confirmed transaction",
                 lambda: chain.add_transaction(tx), "already confirmed")
        print("PASS: all five attacks rejected; original chain is valid.")
        validate_chain(chain.chain)


def api(url, route, payload=None):
    response = (requests.get(url + route, timeout=60) if payload is None else
                requests.post(url + route, json=payload, timeout=60))
    if not response.ok:
        raise RuntimeError(f"{url}{route}: {response.status_code} {response.text}")
    return response.json()


def print_states(label, urls):
    print(label, flush=True)
    states = [api(url, "/status") for url in urls]
    for state in states:
        print(f"  port={state['url'].rsplit(':', 1)[1]} height={state['height']} "
              f"work={state['work']} tip={state['tip']} mempool={state['mempool_size']}", flush=True)
    return states


def fork():
    with tempfile.TemporaryDirectory(prefix="blockchain_fork_") as temporary:
        with Network(temporary) as network:
            a, b, c = network.urls
            alice, alice_addr = wallet()
            _, bob_addr = wallet()
            api(a, "/mine", {"miner": alice_addr})
            states = print_states("BEFORE PARTITION: common funded chain", network.urls)
            assert len({s["tip"] for s in states}) == 1

            api(a, "/peers/pause", {"paused": True})
            tx = sign_transaction(alice, bob_addr, 10, 2, 1)
            identifier = api(a, "/transactions", tx)["txid"]
            api(a, "/mine", {"miner": alice_addr})
            api(b, "/mine", {"miner": bob_addr})
            api(b, "/mine", {"miner": bob_addr})
            states = print_states("DURING PARTITION: A has transaction; B/C have more work", network.urls)
            assert states[0]["tip"] != states[1]["tip"] == states[2]["tip"]

            api(a, "/peers/pause", {"paused": False})
            result = api(a, "/sync", {})
            assert result["changed"]
            pool = api(a, "/mempool")["transactions"]
            assert identifier in [txid(t) for t in pool]
            print("ORPHAN TRANSACTION RETURNED TO A MEMPOOL: " + identifier, flush=True)
            for url in (b, c):
                assert identifier in [txid(t) for t in api(url, "/mempool")["transactions"]]
            print("Returned transaction automatically relayed to B and C.", flush=True)
            for url in network.urls:
                api(url, "/sync", {})
            states = print_states("AFTER SYNCHRONIZATION: common tip", network.urls)
            assert len({s["tip"] for s in states}) == 1

            block = api(a, "/mine", {"miner": alice_addr})["block"]
            assert identifier in [txid(t) for t in block["transactions"]]
            states = print_states("ORPHAN TRANSACTION CONFIRMED AGAIN", network.urls)
            assert len({s["tip"] for s in states}) == 1
            for url in network.urls:
                assert api(url, "/validate")["valid"]
                assert not api(url, "/mempool")["transactions"]
            print("PASS: three processes converged; returned transaction confirmed.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("demo", choices=["attacks", "fork"])
    args = parser.parse_args()
    {"attacks": attacks, "fork": fork}[args.demo]()

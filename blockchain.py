"""Навчальний блокчейн: правила консенсусу без готових blockchain-бібліотек."""
from __future__ import annotations

import copy
import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class Invalid(ValueError):
    """Причина відхилення, яку також повертає REST API."""


def require(condition, reason):
    if not condition:
        raise Invalid(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def txid(tx):
    return sha(canonical(tx))


def address(public_key):
    return sha(bytes.fromhex(public_key))


def is_hex(value, length=64):
    return (isinstance(value, str) and len(value) == length
            and all(c in "0123456789abcdef" for c in value))


def merkle_root(hashes):
    level = list(hashes)
    if not level:
        return sha(b"")
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha(bytes.fromhex(level[i]) + bytes.fromhex(level[i + 1]))
                 for i in range(0, len(level), 2)]
    return level[0]


def merkle_proof(hashes, index):
    require(0 <= index < len(hashes), "Merkle index out of range")
    proof, level = [], list(hashes)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        proof.append({"side": "left" if index % 2 else "right",
                      "hash": level[index ^ 1]})
        level = [sha(bytes.fromhex(level[i]) + bytes.fromhex(level[i + 1]))
                 for i in range(0, len(level), 2)]
        index //= 2
    return proof


def verify_proof(transaction_id, proof, root):
    try:
        current = transaction_id
        for step in proof:
            if step["side"] not in ("left", "right"):
                return False
            left, right = ((step["hash"], current) if step["side"] == "left"
                           else (current, step["hash"]))
            current = sha(bytes.fromhex(left) + bytes.fromhex(right))
        return current == root
    except (ValueError, TypeError, KeyError):
        return False


@dataclass(frozen=True)
class Rules:
    initial_difficulty: int = 2
    interval: int = 5
    target_ms: int = 10_000
    max_difficulty: int = 6
    reward: int = 50
    max_transactions: int = 3


DEFAULT_RULES = Rules()
HEADER_FIELDS = {"index", "timestamp", "previous_hash", "merkle_root", "difficulty", "nonce"}
TX_FIELDS = {"type", "sender", "recipient", "amount", "fee", "nonce", "public_key", "signature"}


def genesis():
    header = {"index": 0, "timestamp": 1_700_000_000_000,
              "previous_hash": "0" * 64, "merkle_root": merkle_root([]),
              "difficulty": 0, "nonce": 0}
    return {"header": header, "hash": sha(canonical(header)), "transactions": []}


def next_difficulty(chain, rules=DEFAULT_RULES):
    count = len(chain) - 1
    if not count:
        return rules.initial_difficulty
    difficulty = chain[-1]["header"]["difficulty"]
    if count % rules.interval == 0:
        # K блоків дають K-1 інтервалів. Час генезису не впливає на оцінку.
        elapsed = chain[-1]["header"]["timestamp"] - chain[-rules.interval]["header"]["timestamp"]
        expected = rules.target_ms * (rules.interval - 1)
        if elapsed < expected / 2:
            difficulty += 1
        elif elapsed > expected * 2:
            difficulty -= 1
    return max(1, min(rules.max_difficulty, difficulty))


def mine_header(header):
    """Повертає новий заголовок і хеш; початковий словник не змінює."""
    header = dict(header)
    header["nonce"] = 0
    prefix = "0" * header["difficulty"]
    while True:
        digest = sha(canonical(header))
        if digest.startswith(prefix):
            return header, digest
        header["nonce"] += 1


def chain_work(chain):
    # Спільний генезис не додає роботи жодній гілці.
    return sum(16 ** b["header"]["difficulty"] for b in chain[1:])


def verify_signature(tx):
    require(isinstance(tx, dict) and set(tx) == TX_FIELDS, "invalid transaction fields")
    require(tx["type"] == "transfer", "expected ordinary transfer")
    require(is_hex(tx["sender"]) and is_hex(tx["recipient"]), "invalid address")
    require(is_hex(tx["public_key"]), "invalid public key")
    require(address(tx["public_key"]) == tx["sender"], "public key does not match sender address")
    require(type(tx["amount"]) is int and tx["amount"] > 0, "amount must be a positive integer")
    require(type(tx["fee"]) is int and tx["fee"] >= 0, "fee must be a nonnegative integer")
    require(type(tx["nonce"]) is int and tx["nonce"] >= 1, "nonce must be a positive integer")
    require(is_hex(tx["signature"], 128), "invalid signature encoding")
    unsigned = {k: v for k, v in tx.items() if k != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(tx["public_key"])).verify(
            bytes.fromhex(tx["signature"]), canonical(unsigned))
    except (InvalidSignature, ValueError):
        raise Invalid("invalid Ed25519 signature") from None


def apply_transfer(tx, balances, nonces, seen):
    verify_signature(tx)
    sender = tx["sender"]
    expected = nonces.get(sender, 0) + 1
    require(tx["nonce"] == expected, f"invalid nonce: expected {expected}, got {tx['nonce']}")
    require(txid(tx) not in seen, "duplicate transaction in chain")
    cost = tx["amount"] + tx["fee"]
    require(balances.get(sender, 0) >= cost, "insufficient balance including fee")
    balances[sender] = balances.get(sender, 0) - cost
    recipient = tx["recipient"]
    balances[recipient] = balances.get(recipient, 0) + tx["amount"]
    nonces[sender] = tx["nonce"]
    seen.add(txid(tx))


def validate_headers(blocks, rules=DEFAULT_RULES):
    """Також використовується легким клієнтом без тіл блоків."""
    require(isinstance(blocks, list) and bool(blocks), "empty chain")
    first = genesis()
    require(blocks[0]["header"] == first["header"] and blocks[0]["hash"] == first["hash"],
            "genesis mismatch")
    now = int(time.time() * 1000)
    for index, block in enumerate(blocks):
        h = block["header"]
        require(isinstance(h, dict) and set(h) == HEADER_FIELDS, "invalid header fields")
        require(all(type(h[k]) is int for k in ("index", "timestamp", "difficulty", "nonce")),
                "header numbers must be integers")
        require(h["index"] == index and h["nonce"] >= 0, "invalid block index or nonce")
        require(is_hex(h["merkle_root"]) and is_hex(h["previous_hash"]), "invalid header hash encoding")
        if index:
            previous = blocks[index - 1]
            require(h["previous_hash"] == previous["hash"], f"broken previous_hash link at block {index}")
            require(previous["header"]["timestamp"] < h["timestamp"] <= now + 120_000,
                    "invalid timestamp: must increase and not exceed future limit")
            require(h["difficulty"] == next_difficulty(blocks[:index], rules), "unexpected difficulty")
        require(block["hash"] == sha(canonical(h)), f"header hash mismatch at block {index}")
        require(block["hash"].startswith("0" * h["difficulty"]), f"invalid Proof of Work at block {index}")


def validate_chain(chain, rules=DEFAULT_RULES):
    validate_headers(chain, rules)
    require(chain[0] == genesis(), "genesis body mismatch")
    balances, nonces, seen = {}, {}, set()
    for index, block in enumerate(chain[1:], 1):
        require(set(block) == {"header", "hash", "transactions"}, "invalid block fields")
        txs = block["transactions"]
        require(isinstance(txs, list) and 1 <= len(txs) <= rules.max_transactions + 1,
                "block transaction limit exceeded or reward missing")
        require(merkle_root([txid(tx) for tx in txs]) == block["header"]["merkle_root"],
                f"Merkle root mismatch at block {index}")
        reward = txs[0]
        require(isinstance(reward, dict) and set(reward) == {"type", "recipient", "amount", "height"},
                "invalid reward fields")
        require(reward["type"] == "reward" and type(reward["height"]) is int
                and reward["height"] == index and is_hex(reward["recipient"]), "invalid miner reward")
        for tx in txs[1:]:
            apply_transfer(tx, balances, nonces, seen)
        require(type(reward["amount"]) is int and reward["amount"] == rules.reward + sum(tx["fee"] for tx in txs[1:]),
                "incorrect miner reward: expected fixed reward plus fees")
        # Винагороду цього блоку можна витратити лише в наступних блоках.
        recipient = reward["recipient"]
        balances[recipient] = balances.get(recipient, 0) + reward["amount"]
    return balances, nonces, seen


class Blockchain:
    def __init__(self, path=None, rules=DEFAULT_RULES):
        self.rules, self.path = rules, Path(path) if path else None
        self.chain, self.mempool = [genesis()], []
        if self.path and self.path.exists():
            saved = json.loads(self.path.read_text(encoding="utf-8"))
            validate_chain(saved["chain"], rules)
            self.chain = saved["chain"]
            self.rebuild_pool(saved.get("mempool", []))

    def save(self):
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix(".tmp")
            temporary.write_text(json.dumps({"chain": self.chain, "mempool": self.mempool},
                                            ensure_ascii=False, indent=2), encoding="utf-8")
            temporary.replace(self.path)

    def account(self, addr):
        balances, nonces, _ = validate_chain(self.chain, self.rules)
        pending = [tx for tx in self.mempool if tx["sender"] == addr]
        balance = balances.get(addr, 0)
        return {"address": addr, "balance": balance,
                "available": balance - sum(t["amount"] + t["fee"] for t in pending),
                "next_nonce": nonces.get(addr, 0) + len(pending) + 1}

    def add_transaction(self, tx, persist=True):
        verify_signature(tx)
        require(not any(txid(t) == txid(tx) for t in self.mempool), "duplicate transaction in mempool")
        balances, nonces, seen = validate_chain(self.chain, self.rules)
        sender = tx["sender"]
        if txid(tx) in seen:
            raise Invalid(f"invalid nonce: {tx['nonce']} already confirmed; duplicate transaction")
        pending = [t for t in self.mempool if t["sender"] == sender]
        expected = nonces.get(sender, 0) + len(pending) + 1
        require(tx["nonce"] == expected, f"invalid nonce: expected {expected}, got {tx['nonce']}")
        available = balances.get(sender, 0) - sum(t["amount"] + t["fee"] for t in pending)
        require(available >= tx["amount"] + tx["fee"], "insufficient available balance including fees and pending spending")
        self.mempool.append(copy.deepcopy(tx))
        if persist:
            self.save()
        return txid(tx)

    def rebuild_pool(self, transactions):
        self.mempool = []
        # Спочатку відновлюємо нижчі nonce; неприпустимі витрати відкидаємо.
        for tx in sorted(transactions, key=lambda t: t.get("nonce", 0)):
            try:
                self.add_transaction(tx, persist=False)
            except Invalid:
                pass

    def select_transactions(self):
        balances, nonces, seen = validate_chain(self.chain, self.rules)
        remaining, selected = list(self.mempool), []
        while remaining and len(selected) < self.rules.max_transactions:
            eligible = [tx for tx in remaining if tx["nonce"] == nonces.get(tx["sender"], 0) + 1]
            if not eligible:
                break
            # Велика комісія має пріоритет лише серед доступних наступних nonce.
            tx = min(eligible, key=lambda t: (-t["fee"], txid(t)))
            remaining.remove(tx)
            try:
                apply_transfer(tx, balances, nonces, seen)
                selected.append(tx)
            except Invalid:
                continue
        return selected

    def make_block(self, miner, timestamp=None):
        require(is_hex(miner), "invalid miner address")
        txs = self.select_transactions()
        index = len(self.chain)
        reward = {"type": "reward", "recipient": miner, "height": index,
                  "amount": self.rules.reward + sum(tx["fee"] for tx in txs)}
        txs = [reward] + copy.deepcopy(txs)
        header = {"index": index, "timestamp": timestamp if timestamp is not None else max(
            int(time.time() * 1000), self.chain[-1]["header"]["timestamp"] + 1),
            "previous_hash": self.chain[-1]["hash"], "merkle_root": merkle_root([txid(t) for t in txs]),
            "difficulty": next_difficulty(self.chain, self.rules), "nonce": 0}
        header, digest = mine_header(header)
        return {"header": header, "hash": digest, "transactions": txs}

    def add_block(self, block):
        candidate = self.chain + [copy.deepcopy(block)]
        validate_chain(candidate, self.rules)
        self.chain = candidate
        self.rebuild_pool(self.mempool)
        self.save()

    def mine(self, miner, timestamp=None):
        block = self.make_block(miner, timestamp)
        self.add_block(block)
        return block

    def adopt(self, candidate):
        validate_chain(candidate, self.rules)
        old_work, new_work = chain_work(self.chain), chain_work(candidate)
        # Однакова робота: стабільний додатковий критерій для збіжності вузлів.
        if new_work < old_work or (new_work == old_work and candidate[-1]["hash"] >= self.chain[-1]["hash"]):
            return False
        orphaned = [tx for b in self.chain[1:] for tx in b["transactions"][1:]]
        pending = self.mempool + orphaned
        self.chain = copy.deepcopy(candidate)
        self.rebuild_pool(pending)
        self.save()
        return True

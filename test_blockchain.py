"""Перевірки правил консенсусу та REST API (стандартний unittest)."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from blockchain import (Blockchain, Invalid, Rules, address, canonical, chain_work,
                        genesis, merkle_proof, merkle_root, mine_header,
                        next_difficulty, sha, txid, validate_chain, verify_proof,
                        verify_signature)
from light_client import LightClient
from node import create_app
from wallet import public_hex, sign_transaction


FAST = Rules(initial_difficulty=1, interval=5, max_transactions=3)


class BlockchainTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.other = Ed25519PrivateKey.generate()
        self.alice = address(public_hex(self.key))
        self.bob = address(public_hex(self.other))
        self.chain = Blockchain(rules=FAST)
        self.chain.mine(self.alice)

    def transaction(self, amount=10, fee=1, nonce=1, key=None, recipient=None):
        return sign_transaction(key or self.key, recipient or self.bob, amount, fee, nonce)

    def remine(self, block):
        block["header"]["merkle_root"] = merkle_root([txid(t) for t in block["transactions"]])
        block["header"], block["hash"] = mine_header(block["header"])
        return block

    def test_canonical_serialization_and_signature(self):
        self.assertEqual(canonical({"b": 2, "a": 1}), canonical({"a": 1, "b": 2}))
        tx = self.transaction()
        verify_signature(dict(reversed(list(tx.items()))))
        self.assertEqual(self.alice, sha(bytes.fromhex(public_hex(self.key))))

    def test_signature_detects_changed_amount(self):
        tx = self.transaction()
        tx["amount"] += 1
        with self.assertRaisesRegex(Invalid, "signature"):
            self.chain.add_transaction(tx)

    def test_public_key_must_match_sender(self):
        tx = self.transaction()
        tx["sender"] = self.bob
        with self.assertRaisesRegex(Invalid, "does not match"):
            self.chain.add_transaction(tx)

    def test_merkle_even(self):
        leaves = [sha(bytes([i])) for i in range(4)]
        left = sha(bytes.fromhex(leaves[0]) + bytes.fromhex(leaves[1]))
        right = sha(bytes.fromhex(leaves[2]) + bytes.fromhex(leaves[3]))
        self.assertEqual(merkle_root(leaves), sha(bytes.fromhex(left) + bytes.fromhex(right)))

    def test_merkle_odd_duplicates_last(self):
        leaves = [sha(bytes([i])) for i in range(3)]
        left = sha(bytes.fromhex(leaves[0]) + bytes.fromhex(leaves[1]))
        right = sha(bytes.fromhex(leaves[2]) * 2)
        self.assertEqual(merkle_root(leaves), sha(bytes.fromhex(left) + bytes.fromhex(right)))

    def test_merkle_empty_single_and_five_leaves(self):
        self.assertEqual(merkle_root([]), sha(b""))
        leaves = [sha(bytes([i])) for i in range(5)]
        self.assertEqual(merkle_root(leaves[:1]), leaves[0])
        for index in range(5):
            self.assertTrue(verify_proof(leaves[index], merkle_proof(leaves, index), merkle_root(leaves)))

    def test_balance_reserves_fees_and_pending_cost(self):
        self.chain.add_transaction(self.transaction(amount=30, fee=2))
        self.assertEqual(self.chain.account(self.alice)["available"], 18)
        with self.assertRaisesRegex(Invalid, "pending spending"):
            self.chain.add_transaction(self.transaction(amount=18, fee=1, nonce=2))

    def test_insufficient_confirmed_balance(self):
        with self.assertRaisesRegex(Invalid, "balance"):
            self.chain.add_transaction(self.transaction(amount=50, fee=1))

    def test_pending_incoming_is_not_spendable(self):
        self.chain.add_transaction(self.transaction())
        with self.assertRaisesRegex(Invalid, "balance"):
            self.chain.add_transaction(self.transaction(amount=1, fee=0, key=self.other, recipient=self.alice))

    def test_duplicate_mempool(self):
        tx = self.transaction()
        self.chain.add_transaction(tx)
        with self.assertRaisesRegex(Invalid, "duplicate"):
            self.chain.add_transaction(tx)

    def test_confirmed_replay_nonce(self):
        tx = self.transaction()
        self.chain.add_transaction(tx)
        self.chain.mine(self.bob)
        with self.assertRaisesRegex(Invalid, "nonce.*already confirmed"):
            self.chain.add_transaction(tx)

    def test_nonce_gap_and_conflict(self):
        with self.assertRaisesRegex(Invalid, "expected 1, got 2"):
            self.chain.add_transaction(self.transaction(nonce=2))
        self.chain.add_transaction(self.transaction())
        with self.assertRaisesRegex(Invalid, "expected 2, got 1"):
            self.chain.add_transaction(self.transaction(amount=2))

    def test_pow_and_hash(self):
        block = self.chain.chain[-1]
        self.assertEqual(block["hash"], sha(canonical(block["header"])))
        self.assertTrue(block["hash"].startswith("0"))
        bad = copy.deepcopy(self.chain.chain)
        while True:
            bad[-1]["header"]["nonce"] += 1
            bad[-1]["hash"] = sha(canonical(bad[-1]["header"]))
            if not bad[-1]["hash"].startswith("0"):
                break
        with self.assertRaisesRegex(Invalid, "Proof of Work"):
            validate_chain(bad, FAST)

    def test_header_hash_mismatch(self):
        bad = copy.deepcopy(self.chain.chain)
        bad[-1]["header"]["nonce"] += 1
        with self.assertRaisesRegex(Invalid, "hash mismatch"):
            validate_chain(bad, FAST)

    def test_remined_block_breaks_next_link(self):
        self.chain.mine(self.bob)
        bad = copy.deepcopy(self.chain.chain)
        bad[1]["header"]["timestamp"] += 1
        bad[1]["header"], bad[1]["hash"] = mine_header(bad[1]["header"])
        with self.assertRaisesRegex(Invalid, "broken previous_hash link"):
            validate_chain(bad, FAST)

    def test_difficulty_retarget_up_and_down(self):
        rules = Rules(initial_difficulty=2, interval=2, target_ms=1000)
        start = genesis()["header"]["timestamp"]
        quick, slow = Blockchain(rules=rules), Blockchain(rules=rules)
        for offset in (100, 200):
            quick.mine(self.alice, start + offset)
        for offset in (100, 3100):
            slow.mine(self.alice, start + offset)
        self.assertEqual(next_difficulty(quick.chain, rules), 3)
        self.assertEqual(next_difficulty(slow.chain, rules), 1)
        quick.mine(self.alice, start + 300)
        slow.mine(self.alice, start + 3200)
        validate_chain(quick.chain, rules)
        validate_chain(slow.chain, rules)

    def test_wrong_difficulty_is_rejected_even_with_valid_pow(self):
        bad = self.chain.make_block(self.bob)
        bad["header"]["difficulty"] = 2
        self.remine(bad)
        with self.assertRaisesRegex(Invalid, "unexpected difficulty"):
            self.chain.add_block(bad)

    def test_reward_and_fees_balances(self):
        self.chain.add_transaction(self.transaction(amount=10, fee=3))
        block = self.chain.mine(self.bob)
        self.assertEqual(block["transactions"][0]["amount"], 53)
        self.assertEqual(self.chain.account(self.alice)["balance"], 37)
        self.assertEqual(self.chain.account(self.bob)["balance"], 63)
        self.assertEqual(sum(validate_chain(self.chain.chain, FAST)[0].values()), 100)

    def test_reward_inflation_rejected(self):
        bad = self.chain.make_block(self.bob)
        bad["transactions"][0]["amount"] += 1
        self.remine(bad)
        with self.assertRaisesRegex(Invalid, "incorrect miner reward"):
            self.chain.add_block(bad)

    def test_old_body_change_detected(self):
        self.chain.add_transaction(self.transaction())
        self.chain.mine(self.bob)
        bad = copy.deepcopy(self.chain.chain)
        bad[-1]["transactions"][1]["amount"] += 1
        with self.assertRaisesRegex(Invalid, "Merkle root mismatch"):
            validate_chain(bad, FAST)

    def test_full_validation_checks_signature_after_remining(self):
        self.chain.add_transaction(self.transaction())
        block = self.chain.make_block(self.bob)
        block["transactions"][1]["signature"] = "ff" * 64
        self.remine(block)
        with self.assertRaisesRegex(Invalid, "signature"):
            self.chain.add_block(block)

    def test_block_rejects_overspend_and_bad_nonce(self):
        for amount, nonce, reason in ((51, 1, "balance"), (1, 2, "nonce")):
            with self.subTest(reason=reason):
                block = self.chain.make_block(self.bob)
                block["transactions"].append(self.transaction(amount=amount, fee=0, nonce=nonce))
                self.remine(block)
                with self.assertRaisesRegex(Invalid, reason):
                    self.chain.add_block(block)

    def test_restart_restores_chain_and_mempool(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "chain.json"
            original = Blockchain(path, FAST)
            original.mine(self.alice)
            original.add_transaction(self.transaction())
            restored = Blockchain(path, FAST)
            self.assertEqual(restored.chain, original.chain)
            self.assertEqual(restored.mempool, original.mempool)
            self.assertEqual(restored.account(self.alice)["available"], 39)

    def test_restart_rejects_corrupted_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "chain.json"
            original = Blockchain(path, FAST)
            original.mine(self.alice)
            data = json.loads(path.read_text())
            data["chain"][-1]["transactions"][0]["amount"] = 999
            path.write_text(json.dumps(data))
            with self.assertRaises(Invalid):
                Blockchain(path, FAST)

    def test_light_client_uses_only_headers_and_detects_false_proof(self):
        self.chain.add_transaction(self.transaction())
        block = self.chain.mine(self.bob)
        headers = [{"header": b["header"], "hash": b["hash"]} for b in self.chain.chain]
        client = LightClient(headers, FAST)
        hashes = [txid(t) for t in block["transactions"]]
        proof = merkle_proof(hashes, 1)
        self.assertTrue(client.contains(2, hashes[1], proof))
        self.assertFalse(client.contains(2, sha(b"fake tx"), proof))
        proof[0]["hash"] = sha(b"fake sibling")
        self.assertFalse(client.contains(2, hashes[1], proof))
        self.assertFalse(client.contains(99, hashes[1], []))
        self.assertNotIn("transactions", client.headers[1])

    def test_fee_selection_preserves_nonce_and_limit(self):
        self.chain.mine(self.bob)
        low = self.transaction(amount=1, fee=1)
        high_child = self.transaction(amount=1, fee=20, nonce=2)
        medium = self.transaction(amount=1, fee=5, key=self.other, recipient=self.alice)
        tail = self.transaction(amount=1, fee=0, nonce=3)
        for tx in (low, high_child, medium, tail):
            self.chain.add_transaction(tx)
        block = self.chain.mine(self.bob)
        self.assertEqual(block["transactions"][1:], [medium, low, high_child])
        self.assertEqual(self.chain.mempool, [tail])

    def test_peer_block_transaction_limit_is_consensus_rule(self):
        block = self.chain.make_block(self.bob)
        for nonce in range(1, 5):
            block["transactions"].append(self.transaction(amount=1, fee=0, nonce=nonce))
        self.remine(block)
        with self.assertRaisesRegex(Invalid, "transaction limit"):
            self.chain.add_block(block)

    def test_shorter_chain_wins_by_accumulated_work(self):
        rules = Rules(initial_difficulty=1, interval=2, target_ms=1000)
        short, long = Blockchain(rules=rules), Blockchain(rules=rules)
        start = genesis()["header"]["timestamp"]
        for offset in (100, 200, 300):
            short.mine(self.alice, start + offset)
        for offset in (100, 3100, 6100, 9100):
            long.mine(self.bob, start + offset)
        validate_chain(short.chain, rules)
        validate_chain(long.chain, rules)
        self.assertLess(len(short.chain), len(long.chain))
        self.assertEqual(chain_work(short.chain), 16 + 16 + 256)
        self.assertEqual(chain_work(long.chain), 4 * 16)
        self.assertTrue(long.adopt(short.chain))
        self.assertEqual(long.chain, short.chain)

    def test_reorg_returns_orphan_and_reconfirms_it(self):
        other = Blockchain(rules=FAST)
        other.chain = copy.deepcopy(self.chain.chain)
        tx = self.transaction()
        self.chain.add_transaction(tx)
        self.chain.mine(self.alice)
        other.mine(self.bob)
        other.mine(self.bob)
        self.assertTrue(self.chain.adopt(other.chain))
        self.assertEqual(self.chain.mempool, [tx])
        self.chain.mine(self.bob)
        self.assertEqual(self.chain.account(self.bob)["balance"], 161)
        self.assertFalse(self.chain.mempool)

    def test_reorg_drops_conflicting_orphan(self):
        other = Blockchain(rules=FAST)
        other.chain = copy.deepcopy(self.chain.chain)
        self.chain.add_transaction(self.transaction(amount=10))
        self.chain.mine(self.alice)
        other.add_transaction(self.transaction(amount=20))
        other.mine(self.bob)
        other.mine(self.bob)
        self.assertTrue(self.chain.adopt(other.chain))
        self.assertEqual(self.chain.mempool, [])

    def test_invalid_heavier_chain_never_adopted(self):
        old = copy.deepcopy(self.chain.chain)
        candidate = copy.deepcopy(old)
        candidate[-1]["header"]["difficulty"] = 6
        with self.assertRaises(Invalid):
            self.chain.adopt(candidate)
        self.assertEqual(self.chain.chain, old)

    def test_genesis_is_identical_and_body_protected(self):
        self.assertEqual(Blockchain().chain[0], self.chain.chain[0])
        bad = [genesis()]
        bad[0]["transactions"] = [self.transaction()]
        with self.assertRaisesRegex(Invalid, "genesis body"):
            validate_chain(bad, FAST)

    def test_invalid_numeric_values(self):
        for amount, fee in ((True, 0), (1.5, 0), (0, 0), (-1, 0), (1, -1)):
            with self.subTest(amount=amount, fee=fee):
                with self.assertRaises(Invalid):
                    self.chain.add_transaction(self.transaction(amount=amount, fee=fee))


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.client = create_app(Path(self.temporary.name) / "chain.json").test_client()
        self.key = Ed25519PrivateKey.generate()
        self.addr = address(public_hex(self.key))

    def test_rest_wallet_mine_balance_validate_headers_proof(self):
        response = self.client.post("/wallets", json={"public_key": public_hex(self.key)})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json["address"], self.addr)
        self.assertNotIn("private_key", response.json)
        block = self.client.post("/mine", json={"miner": self.addr}).json["block"]
        self.assertEqual(self.client.get("/balance/" + self.addr).json["balance"], 50)
        self.assertTrue(self.client.get("/validate").json["valid"])
        headers = self.client.get("/headers").json["headers"]
        identifier = txid(block["transactions"][0])
        proof = self.client.get(f"/proof/1/{identifier}").json["proof"]
        self.assertTrue(LightClient(headers).contains(1, identifier, proof))

    def test_rest_rejection_and_pause(self):
        response = self.client.post("/transactions", json={})
        self.assertEqual(response.status_code, 400)
        self.assertIn("fields", response.json["reason"])
        self.assertTrue(self.client.post("/peers/pause", json={"paused": True}).json["paused"])
        response = self.client.post("/blocks", json={})
        self.assertEqual(response.status_code, 400)
        self.assertIn("paused", response.json["reason"])
        self.assertFalse(self.client.post("/sync", json={}).json["changed"])

    def test_rest_peer_registration(self):
        response = self.client.post("/peers", json={"url": "http://127.0.0.1:8002"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("http://127.0.0.1:8002", self.client.get("/peers").json["peers"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

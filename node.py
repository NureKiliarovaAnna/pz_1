"""Один HTTP-вузол. Стан захищений lock; HTTP-запити виконуються поза lock."""
import argparse
import copy
import logging
import sys
import threading
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request
from werkzeug.exceptions import BadRequest
from werkzeug.serving import make_server

from blockchain import (Blockchain, Invalid, address, chain_work, is_hex,
                        merkle_proof, require, txid, validate_chain)


def create_app(path, peers=(), url="http://127.0.0.1:8001"):
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024
    ledger = Blockchain(path)
    lock = threading.RLock()
    neighbors = set(peers) - {url}
    paused = False

    def body():
        data = request.get_json()
        require(isinstance(data, dict), "JSON object required")
        return data

    @app.errorhandler(Invalid)
    def invalid(error):
        return jsonify({"accepted": False, "reason": str(error)}), 400

    @app.errorhandler(BadRequest)
    def malformed(error):
        return jsonify({"accepted": False, "reason": "invalid JSON request"}), 400

    @app.errorhandler(KeyError)
    @app.errorhandler(TypeError)
    @app.errorhandler(ValueError)
    def invalid_structure(error):
        return jsonify({"accepted": False, "reason": "invalid structure: " + str(error)}), 400

    def snapshot():
        with lock:
            return ([] if paused else sorted(neighbors))

    def broadcast(route, payload):
        errors = {}
        for peer in snapshot():
            try:
                response = requests.post(peer + route, json=payload,
                                         headers={"X-Node-Relay": url}, timeout=15)
                if response.status_code >= 400:
                    errors[peer] = response.json().get("reason", str(response.status_code))
            except (requests.RequestException, ValueError) as error:
                errors[peer] = str(error)
        return errors

    def synchronize():
        changed, errors = False, {}
        restored = {}
        for peer in snapshot():
            try:
                response = requests.get(peer + "/chain", timeout=15)
                response.raise_for_status()
                candidate = response.json()["chain"]
                with lock:
                    # Вузол могли від'єднати, поки тривав HTTP-запит.
                    if not paused:
                        old_ids = {txid(tx) for tx in ledger.mempool}
                        adopted = ledger.adopt(candidate)
                        changed = adopted or changed
                        if adopted:
                            restored.update({txid(tx): copy.deepcopy(tx) for tx in ledger.mempool
                                             if txid(tx) not in old_ids})
            except (requests.RequestException, ValueError, KeyError, TypeError) as error:
                errors[peer] = str(error)
        # Повернені транзакції автоматично отримують і сусіди.
        for tx in restored.values():
            broadcast("/transactions", tx)
        return {"changed": changed, "errors": errors}

    app.synchronize = synchronize

    @app.get("/status")
    def status():
        with lock:
            return jsonify({"url": url, "height": len(ledger.chain) - 1,
                            "tip": ledger.chain[-1]["hash"], "work": chain_work(ledger.chain),
                            "mempool_size": len(ledger.mempool), "paused": paused,
                            "peers": sorted(neighbors)})

    @app.post("/wallets")
    def wallets():
        public = body()["public_key"]
        require(is_hex(public), "invalid Ed25519 public key")
        return jsonify({"address": address(public), "public_key": public}), 201

    @app.get("/balance/<addr>")
    def balance(addr):
        require(is_hex(addr), "invalid address")
        with lock:
            return jsonify(ledger.account(addr))

    @app.get("/mempool")
    def mempool():
        with lock:
            return jsonify({"transactions": copy.deepcopy(ledger.mempool)})

    @app.post("/transactions")
    def transaction():
        tx = body()
        with lock:
            require(not (paused and request.headers.get("X-Node-Relay")), "peer connections temporarily paused")
            identifier = ledger.add_transaction(tx)
        errors = broadcast("/transactions", tx)
        return jsonify({"accepted": True, "txid": identifier, "relay_errors": errors}), 201

    @app.post("/mine")
    def mine():
        miner = body()["miner"]
        # Створюємо знімок, щоб довгий PoW не блокував приймання мережевих запитів.
        with lock:
            working = Blockchain(rules=ledger.rules)
            working.chain, working.mempool = copy.deepcopy(ledger.chain), copy.deepcopy(ledger.mempool)
        block = working.make_block(miner)
        with lock:
            ledger.add_block(block)  # Застарілий результат буде відхилено.
        errors = broadcast("/blocks", block)
        return jsonify({"block": block, "relay_errors": errors}), 201

    @app.post("/blocks")
    def receive_block():
        block = body()
        with lock:
            require(not paused, "peer connections temporarily paused")
            if any(b["hash"] == block.get("hash") for b in ledger.chain):
                return jsonify({"accepted": True, "known": True})
            try:
                ledger.add_block(block)
                accepted, reason = True, None
            except Invalid as error:
                accepted, reason = False, str(error)
        if accepted:
            broadcast("/blocks", block)
            return jsonify({"accepted": True}), 201
        # Блок іншої гілки не додаємо навмання: завантажуємо і перевіряємо всю гілку.
        result = synchronize()
        with lock:
            accepted = any(b["hash"] == block.get("hash") for b in ledger.chain)
        return jsonify({"accepted": accepted, "reason": reason, "sync": result}), 200 if accepted else 400

    @app.get("/chain")
    def chain():
        with lock:
            return jsonify({"chain": copy.deepcopy(ledger.chain), "work": chain_work(ledger.chain)})

    @app.get("/headers")
    def headers():
        with lock:
            return jsonify({"headers": [{"header": b["header"], "hash": b["hash"]} for b in ledger.chain]})

    @app.get("/proof/<int:height>/<identifier>")
    def proof(height, identifier):
        with lock:
            require(0 <= height < len(ledger.chain), "block not found")
            block = ledger.chain[height]
            hashes = [txid(tx) for tx in block["transactions"]]
            require(identifier in hashes, "transaction not found in block")
            return jsonify({"height": height, "txid": identifier,
                            "proof": merkle_proof(hashes, hashes.index(identifier))})

    @app.get("/validate")
    def validate():
        with lock:
            validate_chain(ledger.chain, ledger.rules)
        return jsonify({"valid": True})

    @app.get("/peers")
    def peers_list():
        with lock:
            return jsonify({"peers": sorted(neighbors), "paused": paused})

    @app.post("/peers")
    def add_peer():
        peer = body()["url"].rstrip("/")
        parsed = urlparse(peer)
        require(parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost")
                and parsed.port is not None and not parsed.path, "peer must be a local HTTP URL with port")
        require(peer != url, "cannot add self as peer")
        with lock:
            neighbors.add(peer)
        return jsonify({"peers": sorted(neighbors)})

    @app.post("/peers/pause")
    def pause():
        nonlocal paused
        value = body()["paused"]
        require(type(value) is bool, "paused must be boolean")
        with lock:
            paused = value
        return jsonify({"paused": paused})

    @app.post("/sync")
    def sync():
        return jsonify(synchronize())

    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8001)
    parser.add_argument("--data", default=None)
    parser.add_argument("--peers", nargs="*", default=[])
    parser.add_argument("--sync-interval", type=float, default=3)
    parser.add_argument("--managed", action="store_true", help="Stop when the parent closes stdin")
    args = parser.parse_args()
    app = create_app(args.data or f"data/node_{args.port}.json", args.peers,
                     f"http://127.0.0.1:{args.port}")
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    if args.sync_interval > 0:
        def periodic_sync():
            while True:
                threading.Event().wait(args.sync_interval)
                app.synchronize()
        threading.Thread(target=periodic_sync, daemon=True).start()
    server = make_server("127.0.0.1", args.port, app, threaded=True)
    if args.managed:
        def watch_parent():
            # EOF — батьківський launcher завершив роботу. HTTP shutdown-маршрут не потрібен.
            sys.stdin.buffer.read()
            server.shutdown()
        threading.Thread(target=watch_parent, daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

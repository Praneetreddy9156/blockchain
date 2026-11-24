"""AeroTrace Simple - the web server and the network.

The Network class is the whole consortium in one place: five members (each with a key and a peer),
an orderer that seals blocks, and the shared chain. Every action goes through submit():

    1. the member signs the transaction          (Ed25519)
    2. the safety rules are checked              (rules.check)
    3. every member's peer re-checks and approves (needs 3 of 5, including the regulator)
    4. the orderer seals a new block              (Merkle root, block hash, signature)
    5. the block is added and the parts updated   (rules.apply)

Run:  python -m uvicorn app:app --port 8100     then open http://localhost:8100
"""
# =====================================================================================================
# HOW TO EXPLAIN THIS FILE
# This file CONNECTS the blockchain (blockchain.py) with the rules (rules.py).
#   - Network.start_fresh()  -> STEP 0: creates the keys and block 0 (the genesis block)
#   - Network.submit()       -> STEPS 1-5 for every action: sign -> rules -> approve -> seal -> add
#   - tamper_test()          -> shows that editing an old block is detected
#   - check_document()       -> compares a certificate's fingerprint with the one on the chain
#   - create_app()           -> the web addresses (API) that the dashboard calls
# Line to remember: Block 0 -> Sign -> Rules -> Approve -> Seal -> Add and update -> Verify
# =====================================================================================================
from __future__ import annotations

import json
import os
import threading                     # for the lock: only one change to the chain at a time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI          # FastAPI: the web framework that answers the dashboard's requests
from fastapi.staticfiles import StaticFiles   # serves the dashboard files (HTML, CSS, JavaScript)
from pydantic import BaseModel       # checks that incoming requests have the right fields

import blockchain as bc              # our blockchain: hashing, signatures, blocks, the chain
import rules                         # our smart-contract rules

HERE = Path(__file__).resolve().parent
SAMPLES = HERE / "samples"           # the sample certificate PDFs
# The approval rule (consensus policy): at least 3 of the 5 members must approve, and one must be the regulator.
# It is written into block 0, so nobody can quietly change it later.
POLICY = {"min_approvals": 3, "must_include": "REGULATOR"}


def now() -> str:
    # The current time in UTC (world time), e.g. 2026-11-22T10:30:00Z
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Network:
    # The whole network in one object: the members' keys, the chain and the current state of the parts.
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.chain_file = data_dir / "chain.json"   # every block is saved here (no database is needed)
        self.keys_file = data_dir / "keys.json"  # demo private keys: stay on the server, never sent to the browser
        self.lock = threading.RLock()  # one change at a time (re-entrant: reset() calls submit())
        data_dir.mkdir(parents=True, exist_ok=True)
        if self.chain_file.exists() and self.keys_file.exists():
            # The app ran before: load the keys and the chain from the files...
            self.keys = {k: bc.key_from_text(v) for k, v in json.loads(self.keys_file.read_text()).items()}
            self.chain = bc.Blockchain.from_list(json.loads(self.chain_file.read_text()))
            self.parts = rules.replay(self.chain)  # current state = replay of the chain (no database)
        else:
            # First run (or after Reset): build a brand-new network.
            self.start_fresh()

    # ------------------------------------------------------------------ setup
    # STEP 0 - happens once: create the keys and block 0 (the genesis block).
    def start_fresh(self) -> None:
        """New keys, a genesis block (block 0) and a little demo history."""
        # A key pair for each of the 5 members, plus one for the orderer (who seals blocks).
        self.keys = {member: bc.new_key() for member in rules.MEMBERS}
        self.keys["ORDERER"] = bc.new_key()
        # DEMO ONLY: all private keys are saved in one file. In real life each company keeps its own key.
        self.keys_file.write_text(json.dumps({k: bc.key_to_text(v) for k, v in self.keys.items()}, indent=1))
        # The network's rule book, stored in block 0: the members with their PUBLIC keys,
        # the orderer's public key and the approval policy. Everyone uses these to check signatures.
        settings = {
            "network": "AeroTrace Simple - fictional consortium",
            "members": {m: {**info, "public_key": bc.public_key_of(self.keys[m])} for m, info in rules.MEMBERS.items()},
            "orderer_key": bc.public_key_of(self.keys["ORDERER"]),
            "policy": POLICY,
        }
        # The genesis transaction is signed by the regulator (DAA), which sets up the network.
        genesis = bc.Transaction("GENESIS", "DAA", settings, now())
        genesis.signature = bc.sign(self.keys["DAA"], genesis.fingerprint())
        # Block 0: number 0, points to 64 zeros (there is no block before it), sealed by the orderer.
        self.chain = bc.Blockchain([bc.Block(0, now(), [genesis], bc.ZERO_HASH).seal(self.keys["ORDERER"])])
        self.parts = {}
        # A little demo history, so the dashboard is not empty. It goes through the SAME submit() as
        # everything else, so even the demo data must pass every rule and get approved.
        # The first blade is registered with the fingerprint of samples/certificate_original.pdf.
        certificate = bc.hash_bytes((SAMPLES / "certificate_original.pdf").read_bytes())
        for action, member, data in [
            ("REGISTER", "AEROWORKS", {"serial": "ATX-CFM56-TB90210", "description": "HPT stage-1 turbine blade set",
                                       "max_cycles": 5000, "max_hours": 20000, "certificate": certificate}),
            ("TRANSFER", "AEROWORKS", {"serial": "ATX-CFM56-TB90210", "to": "SKYLINK"}),
            ("INSTALL", "SKYLINK", {"serial": "ATX-CFM56-TB90210", "aircraft": "SL-A320-DEMO1"}),
            ("USAGE", "SKYLINK", {"serial": "ATX-CFM56-TB90210", "cycles": 4200, "hours": 9850}),
            ("REGISTER", "AEROWORKS", {"serial": "ATX-B787-LG7731", "description": "Main landing gear actuator",
                                       "max_cycles": 20000, "max_hours": 60000}),
        ]:
            result = self.submit(action, member, data, save=False)
            assert result["ok"], result          # stop at once if the demo data ever broke a rule
        self.save()                               # result: block 0 + 5 blocks = 6 blocks

    def save(self) -> None:
        # Write the whole chain to data/chain.json.
        self.chain_file.write_text(json.dumps(self.chain.to_list(), indent=1))

    def reset(self) -> None:
        # The Reset button on the Ledger page: throw everything away and start a fresh network.
        with self.lock:
            self.start_fresh()

    # ------------------------------------------------------------------ the five steps
    # STEPS 1-5 - every action (Register, Transfer, Install, Remove, Usage) goes through here.
    def submit(self, action: str, member: str, data: dict, save: bool = True) -> dict:
        # Only the 5 known members can take part (a PERMISSIONED network).
        if member not in rules.MEMBERS:
            return {"ok": False, "rule": "UNKNOWN_MEMBER", "message": f"{member} is not a member of this network."}
        with self.lock:   # one action at a time, so two blocks can never get the same number
            # Pack the action into a transaction: what, who, the details and when.
            tx = bc.Transaction(action, member, data, now())
            # STEP 1 - SIGN: the member signs the transaction's SHA-256 fingerprint with its private key.
            tx.signature = bc.sign(self.keys[member], tx.fingerprint())                 # 1. the member signs
            # STEP 2 - RULES: the smart contract checks the action. If any rule is broken, it is refused
            #          here and NOTHING is written to the chain.
            try:
                rules.check(action, member, data, self.parts)                            # 2. the rules
            except rules.RuleBroken as broken:
                return {"ok": False, "rule": broken.rule, "message": broken.message}
            # STEP 3 - CONSENSUS: each member's peer re-runs the same rules and signs an approval.
            #          verify() later counts the genuine approvals: at least 3, including the regulator.
            #          (Demo: all 5 peers run inside this one program. In real life each company's own
            #           computer would do this check independently.)
            for peer in rules.MEMBERS:                                                   # 3. every peer re-checks...
                rules.check(action, member, data, self.parts)
                tx.approvals.append({"peer": peer, "signature": bc.sign(                 # ...and signs its approval
                    self.keys[peer], bc.approval_fingerprint(tx.fingerprint(), peer))})
            # STEP 4 - SEAL: the orderer builds the next block. It gets the next number and the hash of the
            #          newest block (the link). seal() computes the Merkle root, the block hash and signs it.
            block = bc.Block(self.chain.last.index + 1, now(), [tx], self.chain.last.hash)
            block.seal(self.keys["ORDERER"])                                             # 4. the orderer seals a block
            # STEP 5 - ADD AND UPDATE: add the block to the chain (refused if it does not link), then the
            #          rules' bookkeeper updates the part (holder, aircraft, cycles/hours, automatic retirement).
            self.chain.add(block)                                                        # 5. add it and update the parts
            summary = rules.apply(action, member, data, tx.timestamp, block.index, self.parts)
            if save:
                self.save()                                                              # write the chain to disk
            # The answer shown on the dashboard: ACCEPTED, the block number, its hash and Merkle root, who approved.
            return {"ok": True, "message": summary, "block": block.index, "block_hash": block.hash,
                    "merkle_root": block.merkle_root, "approvals": [rules.MEMBERS[a["peer"]]["name"] for a in tx.approvals]}

    # ------------------------------------------------------------------ demonstrations
    # The Tamper test button (Ledger page): proves that changing history is detected.
    def tamper_test(self) -> dict:
        """On a COPY of the chain: rewrite a usage record, then also try to cover it up."""
        fake = self.chain.copy()                  # work on a copy, so the real chain is never touched
        # Find the first block that records usage (flight cycles and hours).
        target = next((b for b in fake.blocks if b.transactions[0].action == "USAGE"), None)
        if target is None:
            return {"ok": False, "message": "Record some usage first, then run the tamper test."}
        tx = target.transactions[0]
        before = tx.data["cycles"]
        tx.data["cycles"] = max(1, before // 10)                     # the fraud: make the part look younger
        # Attempt 1 - just edit the number. Result: MERKLE_ROOT, TX_SIGNATURE and APPROVALS fail.
        after_edit = fake.verify()
        # Attempt 2 - the cover-up: recompute the Merkle root and hash of this block and every block after it.
        for block in fake.blocks[target.index:]:                      # the cover-up: recompute every hash after it
            block.previous_hash = fake.blocks[block.index - 1].hash
            block.merkle_root = block.compute_merkle_root()
            block.hash = block.compute_hash()                         # ...but nobody can re-sign without the keys
        # Result: the hashes match again, but BLOCK_SIGNATURE, TX_SIGNATURE and APPROVALS still fail,
        # because the forger does not have the private keys to make new signatures.
        after_cover_up = fake.verify()
        return {"ok": True, "block": target.index, "change": f"{before:,} cycles changed to {tx.data['cycles']:,}",
                "after_edit": after_edit, "after_cover_up": after_cover_up}

    # The Documents page: is this file the original certificate?
    # The browser has already computed the file's SHA-256 (the file itself is never uploaded).
    def check_document(self, serial: str, sha256: str) -> dict:
        part = self.parts.get(serial.strip().upper())
        if part is None or not part["certificate"]:
            return {"ok": False, "message": "This part has no certificate fingerprint on the ledger."}
        # Compare the file's fingerprint with the one stored on the chain when the part was registered.
        match = sha256.lower() == part["certificate"]              # same -> MATCH, different -> MISMATCH
        return {"ok": True, "match": match, "on_chain": part["certificate"], "file": sha256.lower(),
                "bits_different": bc.bits_different(sha256.lower(), part["certificate"])}   # 0 bits = identical


# ---------------------------------------------------------------------- the web API
# The shape of the requests the dashboard sends. FastAPI refuses a request with missing or wrong fields.
class ActionIn(BaseModel):
    action: str      # e.g. "REGISTER"
    member: str      # e.g. "AEROWORKS"
    data: dict = {}  # e.g. {"serial": "ATX-DEMO-0001", ...}


class DocumentIn(BaseModel):
    serial: str      # which part
    sha256: str      # the file's fingerprint, computed in the browser


def create_app(data_dir: Path) -> FastAPI:
    # Build the web server. The dashboard (static/app.js) talks to the network only through these addresses.
    network = Network(data_dir)
    api = FastAPI(title="AeroTrace Simple")
    api.state.network = network

    @api.get("/api/state")                 # the current picture: members, parts, number of blocks, chain valid?
    def state():
        report = network.chain.verify()
        return {"members": [{"id": m, **info} for m, info in rules.MEMBERS.items()],
                "actions": {a: info["label"] for a, info in rules.ACTIONS.items()},
                "parts": list(network.parts.values()), "blocks": len(network.chain.blocks),
                "valid": report["valid"], "tip": network.chain.last.hash, "policy": POLICY}

    @api.get("/api/blocks")                # every block, newest first (the Ledger page)
    def blocks():
        return list(reversed(network.chain.to_list()))

    @api.post("/api/action")               # do an action -> the 5 steps in submit() (the Actions page)
    def action(body: ActionIn):
        return network.submit(body.action, body.member, body.data)

    @api.post("/api/verify")               # run the 8 checks on the whole chain (Verify button)
    def verify():
        return network.chain.verify()

    @api.post("/api/tamper-test")          # the tamper demonstration (Tamper test button)
    def tamper_test():
        return network.tamper_test()

    @api.post("/api/check-document")       # compare a certificate's fingerprint (the Documents page)
    def check_document(body: DocumentIn):
        return network.check_document(body.serial, body.sha256)

    @api.post("/api/reset")                # start again with a fresh chain (Reset button)
    def reset():
        network.reset()
        return {"ok": True}

    api.mount("/samples", StaticFiles(directory=SAMPLES), name="samples")             # the sample PDFs to download
    api.mount("/", StaticFiles(directory=HERE / "static", html=True), name="dashboard")  # the dashboard itself
    return api


# The app that uvicorn runs. AEROTRACE_DATA lets the tests use a temporary folder instead of data/.
app = create_app(Path(os.environ.get("AEROTRACE_DATA", HERE / "data")))

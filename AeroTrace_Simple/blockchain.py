
# =====================================================================================================
# HOW TO EXPLAIN THIS FILE
# This file is the blockchain itself. It knows nothing about aircraft parts or rules; it only knows how
# to fingerprint data, sign it, pack it into blocks, link the blocks and check that nothing was changed.
# The rules about parts live in rules.py, and app.py connects the two.
# Order to read it: fingerprints -> Merkle root -> signatures -> transactions and blocks -> the chain.
# =====================================================================================================
from __future__ import annotations

import hashlib                       # Python's built-in SHA-256 (no extra install needed)
import json                          # turns Python data into text, so it can be hashed and saved
from dataclasses import dataclass, field

# The "cryptography" library gives us Ed25519 digital signatures.
# We use a well-tested library because you should never write your own cryptography.
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ZERO_HASH = "0" * 64  # block 0 has no previous block, so it points to 64 zeros


# ----------------------------------------------------------------------------- 1. fingerprints
# SHA-256 turns ANY data into a fixed 256-bit "fingerprint", written as 64 hexadecimal characters.
#   - Same data in  -> always the same fingerprint out.
#   - Change one character -> about half of the 256 bits change (the "avalanche effect").
#   - It is one-way: you cannot get the data back from the fingerprint.
#   - Finding two different files with the same fingerprint is practically impossible.
def hash_bytes(raw: bytes) -> str:
    """SHA-256 fingerprint of raw bytes (64 hex characters = 256 bits)."""
    return hashlib.sha256(raw).hexdigest()        # hexdigest() = the 256 bits written as 64 hex characters


def hash_data(data) -> str:
    """SHA-256 fingerprint of any Python data. Keys are sorted and spaces removed,
    so every computer turns the same data into exactly the same bytes."""
    # Step 1: write the data as text in ONE fixed way (sorted keys, no spaces).
    #         Without this, {"a":1,"b":2} and {"b":2,"a":1} would give different fingerprints.
    text = json.dumps(data, sort_keys=True, separators=(",", ":"))
    # Step 2: fingerprint that text.
    return hash_bytes(text.encode("utf-8"))


def bits_different(hash_a: str, hash_b: str) -> int:
    """How many of the 256 bits differ between two fingerprints (the avalanche effect)."""
    # XOR (^) gives a 1 wherever the two fingerprints differ; then we count the 1s.
    # Used on the Documents page: e.g. the altered new-part certificate differs in 118 of 256 bits.
    return bin(int(hash_a, 16) ^ int(hash_b, 16)).count("1")


# ----------------------------------------------------------------------------- 2. Merkle root
# A Merkle root is ONE fingerprint that stands for ALL the transactions in a block.
# Picture a tournament bracket: hash the transactions in pairs, then hash those results in pairs,
# until one hash is left at the top. Change any transaction and the root changes.
# (In this project each block holds one transaction, so the root is that transaction's hash,
#  but the function works for any number of transactions.)
def merkle_root(leaf_hashes: list[str]) -> str:
    """Hash the leaves in pairs, then the pairs, until one hash is left: the Merkle root.
    If a level has an odd number of hashes, the last one is paired with itself."""
    if not leaf_hashes:                       # no transactions at all: use the hash of "nothing"
        return hash_bytes(b"")
    level = list(leaf_hashes)                 # the bottom row of the bracket
    while len(level) > 1:                     # keep going until one hash is left
        if len(level) % 2 == 1:               # odd number? copy the last one so every hash has a partner
            level.append(level[-1])
        # join each pair of hashes and fingerprint them -> the next row up (half as long)
        level = [hash_bytes(bytes.fromhex(level[i]) + bytes.fromhex(level[i + 1]))
                 for i in range(0, len(level), 2)]
    return level[0]                           # the top of the bracket = the Merkle root


# ----------------------------------------------------------------------------- 3. signatures
# A digital signature proves WHO did something and that it was not changed afterwards.
# Each member has a key pair:
#   - private key (secret, 32 bytes): used to SIGN
#   - public key (shared with everyone in block 0, 32 bytes): used by anyone to CHECK a signature
# We use Ed25519 instead of RSA: much smaller keys and signatures (64 bytes), fast, no risky settings
# to choose, and about the same security as RSA-3072. (This is signing, not encryption: nothing is hidden.)
def new_key() -> Ed25519PrivateKey:
    """A new Ed25519 key pair. The private key signs; the public key lets anyone check."""
    return Ed25519PrivateKey.generate()


def public_key_of(key: Ed25519PrivateKey) -> str:
    # The public half of a key pair, as 64 hex characters. These go into block 0 for everyone to use.
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return raw.hex()


def key_to_text(key: Ed25519PrivateKey) -> str:
    # Turn a private key into text so it can be saved in data/keys.json.
    # DEMO ONLY: the keys are saved unencrypted on one computer. In real life each company keeps its own.
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    return raw.hex()


def key_from_text(text: str) -> Ed25519PrivateKey:
    # The opposite of key_to_text(): load a saved private key.
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(text))


def sign(key: Ed25519PrivateKey, fingerprint: str) -> str:
    """Sign a fingerprint ("hash-then-sign"). Only the private key's owner can do this."""
    # We sign the 32-byte SHA-256 fingerprint, not the whole data: it is short and stands for the data.
    return key.sign(bytes.fromhex(fingerprint)).hex()    # the signature: 64 bytes = 128 hex characters


def verify(public_key: str, fingerprint: str, signature: str) -> bool:
    """True only if this signature was made over this fingerprint by this key's owner."""
    try:
        # Rebuild the public key, then ask: "was this signature made by its private key, over this fingerprint?"
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(
            bytes.fromhex(signature), bytes.fromhex(fingerprint))
        return True                                      # genuine
    except (InvalidSignature, ValueError):               # wrong key, changed data, or broken text
        return False                                     # fake or tampered


def approval_fingerprint(tx_fingerprint: str, peer: str) -> str:
    """What a peer signs to say "I re-checked this transaction and approve it"."""
    # The peer's name and the word APPROVE are mixed in, so an approval cannot be copied
    # to another transaction or passed off as another peer's approval.
    return hash_data({"transaction": tx_fingerprint, "peer": peer, "decision": "APPROVE"})


# ----------------------------------------------------------------------------- 4. transactions and blocks
# A TRANSACTION is one event in a part's life ("AeroWorks registered blade TB90210").
# A BLOCK is a sealed page in the ledger that holds transactions and points to the page before it.
@dataclass
class Transaction:
    """One event in a part's life, e.g. REGISTER or USAGE."""
    action: str          # what happened: REGISTER, TRANSFER, INSTALL, REMOVE or USAGE (or GENESIS in block 0)
    member: str          # the organisation that did it (and signed it)
    data: dict           # the details: serial number, cycles, ...
    timestamp: str       # when it happened (UTC)
    signature: str = ""  # the member's signature over fingerprint()
    approvals: list[dict] = field(default_factory=list)  # [{"peer": ..., "signature": ...}]

    def body(self) -> dict:
        # The part the member signs. The signature itself is not inside (a signature cannot sign itself).
        return {"action": self.action, "member": self.member, "data": self.data, "timestamp": self.timestamp}

    def fingerprint(self) -> str:
        """The value the member signs: the SHA-256 of the body."""
        return hash_data(self.body())

    def leaf(self) -> str:
        """The Merkle leaf: covers the body, the signature and the approvals."""
        # Because the leaf includes the signature and approvals, the Merkle root protects them too.
        return hash_data(self.to_dict())

    def to_dict(self) -> dict:
        # Everything about the transaction, ready to save as JSON.
        return {**self.body(), "signature": self.signature, "approvals": self.approvals}

    @classmethod
    def from_dict(cls, d: dict) -> "Transaction":
        # The opposite of to_dict(): rebuild a transaction from saved JSON.
        return cls(d["action"], d["member"], d["data"], d["timestamp"], d.get("signature", ""),
                   d.get("approvals", []))


@dataclass
class Block:
    index: int             # the block number: 0, 1, 2, ...
    timestamp: str         # when the block was sealed
    transactions: list[Transaction]
    previous_hash: str     # the hash of the block before: this is what makes it a chain
    merkle_root: str = ""  # one fingerprint for all the transactions
    hash: str = ""         # this block's own fingerprint
    signature: str = ""    # the orderer's signature over the hash

    def header(self) -> dict:
        # The block's "cover page". It holds the previous block's hash (the link) and the Merkle root
        # (which stands for all the transactions). So the block hash below protects EVERYTHING.
        return {"index": self.index, "timestamp": self.timestamp,
                "previous_hash": self.previous_hash, "merkle_root": self.merkle_root}

    def compute_merkle_root(self) -> str:
        # Recalculate the Merkle root from the transactions as they are NOW.
        return merkle_root([tx.leaf() for tx in self.transactions])

    def compute_hash(self) -> str:
        # The block's fingerprint = SHA-256 of its header.
        return hash_data(self.header())

    def seal(self, orderer_key: Ed25519PrivateKey) -> "Block":
        """Finish the block: Merkle root, then block hash, then the orderer signs the hash."""
        # The order matters: the hash needs the Merkle root, and the signature needs the hash.
        self.merkle_root = self.compute_merkle_root()      # 1. one fingerprint for all transactions
        self.hash = self.compute_hash()                     # 2. the block's own fingerprint
        self.signature = sign(orderer_key, self.hash)       # 3. the orderer signs it: "I sealed this block"
        return self

    def to_dict(self) -> dict:
        # The whole block as JSON (this is what you see on the Ledger page and in data/chain.json).
        return {**self.header(), "hash": self.hash, "signature": self.signature,
                "transactions": [tx.to_dict() for tx in self.transactions]}

    @classmethod
    def from_dict(cls, d: dict) -> "Block":
        # The opposite of to_dict(): rebuild a block from saved JSON.
        return cls(d["index"], d["timestamp"], [Transaction.from_dict(t) for t in d["transactions"]],
                   d["previous_hash"], d["merkle_root"], d["hash"], d["signature"])


# ----------------------------------------------------------------------------- 5. the chain
# The 8 checks that verify() runs on every block. If someone edits anything, at least one fails.
CHECKS = {
    "GENESIS": "Block 0 is the genesis block and points to 64 zeros",
    "ORDER": "Block numbers go up by exactly one",
    "LINK": "Every block stores the exact hash of the block before it",
    "MERKLE_ROOT": "Each Merkle root still matches its transactions",
    "BLOCK_HASH": "Each block hash still matches its block header",
    "BLOCK_SIGNATURE": "The orderer's signature on every block is genuine",
    "TX_SIGNATURE": "Every transaction is signed by the member who made it",
    "APPROVALS": "Every transaction has enough genuine peer approvals, including the regulator's",
}


class Blockchain:
    def __init__(self, blocks: list[Block] | None = None):
        self.blocks: list[Block] = blocks or []        # the chain is simply a list of blocks, oldest first

    @property
    def last(self) -> Block:
        return self.blocks[-1]                         # the newest block (the "tip" of the chain)

    def settings(self) -> dict:
        """The network settings stored in block 0: members, public keys and the approval policy."""
        # Block 0 (the genesis block) is the network's rule book: who the members are, their public keys,
        # the orderer's public key and the approval rule (3 of 5, including the regulator).
        return self.blocks[0].transactions[0].data

    def add(self, block: Block) -> None:
        """Append a new block, but only if it links to the current last block."""
        # A new block must point to the newest block and have the next number; otherwise it is refused.
        if block.previous_hash != self.last.hash or block.index != self.last.index + 1:
            raise ValueError("block does not link to the end of the chain")
        self.blocks.append(block)

    def verify(self) -> dict:
        """Re-check the whole chain from scratch. Any edit anywhere makes at least one check fail."""
        # Nothing is trusted here: every hash and every signature is recalculated from the data itself.
        problems: list[dict] = []

        def problem(check: str, block: int, message: str) -> None:
            problems.append({"check": check, "block": block, "message": message})

        settings = self.settings()                     # read the rule book from block 0
        members = settings["members"]                  # the members and their public keys
        policy = settings["policy"]                    # {"min_approvals": 3, "must_include": "REGULATOR"}
        # Check 1 - GENESIS: block 0 must be number 0 and point to 64 zeros.
        if self.blocks[0].index != 0 or self.blocks[0].previous_hash != ZERO_HASH:
            problem("GENESIS", 0, "block 0 is not a valid genesis block")

        for position, block in enumerate(self.blocks):
            if position > 0:
                before = self.blocks[position - 1]
                # Check 2 - ORDER: block numbers go 0, 1, 2, ... with no gaps.
                if block.index != before.index + 1:
                    problem("ORDER", block.index, "block number is out of order")
                # Check 3 - LINK: this block must hold the exact hash of the block before it.
                if block.previous_hash != before.hash:
                    problem("LINK", block.index, f"does not link to block #{before.index}")
            # Check 4 - MERKLE_ROOT: recalculate it from the transactions; a changed transaction gives a new root.
            if block.compute_merkle_root() != block.merkle_root:
                problem("MERKLE_ROOT", block.index, "a transaction was changed after the block was sealed")
            # Check 5 - BLOCK_HASH: recalculate the block's fingerprint from its header.
            if block.compute_hash() != block.hash:
                problem("BLOCK_HASH", block.index, "the block header was changed")
            # Check 6 - BLOCK_SIGNATURE: the orderer must really have signed this hash.
            #           A forger can recalculate hashes, but cannot sign without the orderer's private key.
            if not verify(settings["orderer_key"], block.hash, block.signature):
                problem("BLOCK_SIGNATURE", block.index, "the orderer never signed this block hash")

            for tx in block.transactions:
                # Check 7 - TX_SIGNATURE: the member named in the transaction must really have signed it.
                member = members.get(tx.member)
                if member is None or not verify(member["public_key"], tx.fingerprint(), tx.signature):
                    problem("TX_SIGNATURE", block.index, f"{tx.action} is not genuinely signed by {tx.member}")
                if tx.action == "GENESIS":
                    continue                           # block 0 sets up the network, so it needs no approvals
                # Check 8 - APPROVALS: count only GENUINE approval signatures (a set, so each peer counts once)...
                approved_by = {a["peer"] for a in tx.approvals
                               if a["peer"] in members and verify(members[a["peer"]]["public_key"],
                                                                  approval_fingerprint(tx.fingerprint(), a["peer"]),
                                                                  a["signature"])}
                roles = {members[p]["role"] for p in approved_by}
                # ...then apply the policy from block 0: at least 3 approvals, and one must be the regulator.
                if len(approved_by) < policy["min_approvals"] or policy["must_include"] not in roles:
                    problem("APPROVALS", block.index,
                            f"{tx.action} has {len(approved_by)} genuine approvals; needs {policy['min_approvals']} "
                            f"including the {policy['must_include'].lower()}")

        # The report shown on the Ledger page: valid or not, and a pass/fail for each of the 8 checks.
        failed = {p["check"] for p in problems}
        return {"valid": not problems, "blocks": len(self.blocks),
                "checks": [{"name": n, "description": d, "passed": n not in failed} for n, d in CHECKS.items()],
                "problems": problems}

    def to_list(self) -> list[dict]:
        # The whole chain as JSON, saved in data/chain.json.
        return [block.to_dict() for block in self.blocks]

    @classmethod
    def from_list(cls, data: list[dict]) -> "Blockchain":
        # Load the chain back from data/chain.json.
        return cls([Block.from_dict(d) for d in data])

    def copy(self) -> "Blockchain":
        """An independent copy (used by the tamper test, so the real chain is never touched)."""
        return Blockchain.from_list(json.loads(json.dumps(self.to_list())))

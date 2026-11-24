"""Tests for AeroTrace Simple. Run:  python -m pytest -q   (from the AeroTrace_Simple folder)"""
import os
import tempfile
from pathlib import Path

os.environ["AEROTRACE_DATA"] = tempfile.mkdtemp(prefix="aerotrace-simple-")  # never touch the real demo data

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import blockchain as bc  # noqa: E402
import rules  # noqa: E402
from app import Network, app  # noqa: E402

SAMPLES = Path(__file__).resolve().parent / "samples"
BLADES = "ATX-CFM56-TB90210"


@pytest.fixture()
def net(tmp_path):
    return Network(tmp_path)


# ---------------------------------------------------------------- the blockchain building blocks
def test_one_changed_byte_changes_the_fingerprint_completely():
    original = (SAMPLES / "certificate_original.pdf").read_bytes()
    altered = (SAMPLES / "certificate_altered.pdf").read_bytes()
    assert len(original) == len(altered) and sum(a != b for a, b in zip(original, altered)) == 1
    assert bc.bits_different(bc.hash_bytes(original), bc.hash_bytes(altered)) == 141


def test_merkle_root_changes_when_any_transaction_changes():
    leaves = [bc.hash_data({"tx": n}) for n in range(5)]
    changed = leaves[:3] + [bc.hash_data({"tx": 99})] + leaves[4:]
    assert bc.merkle_root(leaves) != bc.merkle_root(changed)
    assert bc.merkle_root(leaves[:1]) == leaves[0]


def test_signature_is_valid_only_for_the_signed_data_and_key():
    key, other = bc.new_key(), bc.new_key()
    fingerprint = bc.hash_data({"serial": "X"})
    signature = bc.sign(key, fingerprint)
    assert bc.verify(bc.public_key_of(key), fingerprint, signature)
    assert not bc.verify(bc.public_key_of(other), fingerprint, signature)
    assert not bc.verify(bc.public_key_of(key), bc.hash_data({"serial": "Y"}), signature)


# ---------------------------------------------------------------- the network and the rules
def test_fresh_network_has_a_valid_chain_and_rebuilds_from_disk(net, tmp_path):
    report = net.chain.verify()
    assert report["valid"] and report["blocks"] == 6
    assert all(c["passed"] for c in report["checks"]) and len(report["checks"]) == 8
    reloaded = Network(tmp_path)
    assert reloaded.chain.last.hash == net.chain.last.hash
    assert reloaded.parts[BLADES]["cycles"] == 4200


def test_only_the_manufacturer_can_register(net):
    result = net.submit("REGISTER", "DAA", {"serial": "ATX-NEW-1", "max_cycles": 10, "max_hours": 10})
    assert not result["ok"] and result["rule"] == "ROLE"
    assert net.submit("REGISTER", "AEROWORKS", {"serial": "ATX-NEW-1", "max_cycles": 10, "max_hours": 10})["ok"]


def test_duplicate_serial_is_rejected(net):
    result = net.submit("REGISTER", "AEROWORKS", {"serial": BLADES, "max_cycles": 10, "max_hours": 10})
    assert result["rule"] == "DUPLICATE_SERIAL"


def test_only_the_holder_can_act_and_rejections_change_nothing(net):
    blocks = len(net.chain.blocks)
    result = net.submit("USAGE", "NORTHWIND", {"serial": BLADES, "cycles": 1, "hours": 1})
    assert result["rule"] == "NOT_HOLDER" and len(net.chain.blocks) == blocks


def test_usage_can_never_go_down(net):
    result = net.submit("USAGE", "SKYLINK", {"serial": BLADES, "cycles": -500, "hours": 0})
    assert result["rule"] == "USAGE_ONLY_UP"


def test_reaching_a_limit_retires_the_part_forever(net):
    result = net.submit("USAGE", "SKYLINK", {"serial": BLADES, "cycles": 800, "hours": 500})
    assert result["ok"] and net.parts[BLADES]["state"] == "RETIRED"
    again = net.submit("INSTALL", "NORTHWIND", {"serial": BLADES, "aircraft": "NW-1"})
    assert again["rule"] == "RETIRED_FOREVER"


def test_transfer_then_install_by_the_new_holder(net):
    assert net.submit("TRANSFER", "AEROWORKS", {"serial": "ATX-B787-LG7731", "to": "NORTHWIND"})["ok"]
    assert net.submit("INSTALL", "NORTHWIND", {"serial": "ATX-B787-LG7731", "aircraft": "NW-A320-1"})["ok"]
    assert net.parts["ATX-B787-LG7731"]["state"] == "INSTALLED"
    assert net.submit("TRANSFER", "NORTHWIND", {"serial": "ATX-B787-LG7731", "to": "SKYLINK"})["rule"] == "WRONG_STATE"


def test_every_accepted_action_has_five_approvals(net):
    result = net.submit("REGISTER", "AEROWORKS", {"serial": "ATX-NEW-2", "max_cycles": 10, "max_hours": 10})
    assert len(result["approvals"]) == 5 and len(net.chain.last.transactions[0].approvals) == 5


# ---------------------------------------------------------------- tamper evidence
def test_tamper_is_detected_even_after_recomputing_hashes(net):
    report = net.tamper_test()
    after_edit = {c["name"] for c in report["after_edit"]["checks"] if not c["passed"]}
    after_cover = {c["name"] for c in report["after_cover_up"]["checks"] if not c["passed"]}
    assert {"MERKLE_ROOT", "TX_SIGNATURE", "APPROVALS"} <= after_edit
    assert "MERKLE_ROOT" not in after_cover and "LINK" not in after_cover
    assert {"BLOCK_SIGNATURE", "TX_SIGNATURE"} <= after_cover
    assert net.chain.verify()["valid"]  # the real chain was never touched


def test_rules_replay_matches_live_state(net):
    assert rules.replay(net.chain) == net.parts


def test_document_check(net):
    original = bc.hash_bytes((SAMPLES / "certificate_original.pdf").read_bytes())
    altered = bc.hash_bytes((SAMPLES / "certificate_altered.pdf").read_bytes())
    assert net.check_document(BLADES, original)["match"]
    result = net.check_document(BLADES, altered)
    assert not result["match"] and result["bits_different"] == 141


# ---------------------------------------------------------------- the web API
def test_api_end_to_end():
    client = TestClient(app)
    state = client.get("/api/state").json()
    assert state["valid"] and len(state["members"]) == 5
    rejected = client.post("/api/action", json={"action": "REGISTER", "member": "SKYLINK", "data": {"serial": "ATX-API-1"}}).json()
    assert rejected["rule"] == "ROLE"
    assert client.post("/api/verify").json()["valid"]
    assert client.get("/").status_code == 200 and "AeroTrace" in client.get("/").text

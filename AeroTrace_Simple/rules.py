"""AeroTrace Simple - the safety rules (the "smart contract").

check()   decides whether an action is allowed. Every peer runs it before approving.
apply()   changes the current state of the parts once the action is in a block.
replay()  rebuilds the current state from block 0, so the chain is the only source of truth.

All organisations below are fictional.
"""
# =====================================================================================================
# HOW TO EXPLAIN THIS FILE
# This is the "smart contract": the business rules every member agrees on.
# Think of it as a security guard plus a bookkeeper:
#   check()  = the GUARD.      Runs BEFORE a block is made. If an action breaks a rule, it is refused
#                              and nothing is written to the chain.
#   apply()  = the BOOKKEEPER. Runs AFTER the block is added. It updates the part: who holds it,
#                              which aircraft it is on, its cycles and hours, and retires it at its limit.
#   replay() = rebuilds every part from the chain alone, so the chain is the only source of truth.
# The blockchain (blockchain.py) never decides what is allowed; this file never stores anything.
# A part's life:  REGISTER -> IN_STOCK <-> INSTALLED -> RETIRED (forever)
# =====================================================================================================
from __future__ import annotations

import re                             # regular expressions, used to check the format of serial numbers

# The five members of the network (all fictional) and each one's ROLE.
# The role decides what a member is allowed to do (see ACTIONS below).
MEMBERS = {
    "AEROWORKS": {"name": "AeroWorks OEM", "role": "OEM"},                     # the manufacturer
    "SKYLINK": {"name": "SkyLink Airways", "role": "AIRLINE"},                 # an airline
    "NORTHWIND": {"name": "Northwind Regional Airlines", "role": "AIRLINE"},   # another airline
    "PRECISION": {"name": "Precision MRO", "role": "MRO"},                     # a repair shop (Maintenance, Repair, Overhaul)
    "DAA": {"name": "Demo Aviation Authority", "role": "REGULATOR"},           # the regulator: must approve every block
}

# Which roles may do which action. The regulator is read-only, so it appears nowhere.
ACTIONS = {
    "REGISTER": {"label": "Register a new part", "roles": {"OEM"}},             # only the maker creates a part
    "TRANSFER": {"label": "Transfer to another member", "roles": {"OEM", "AIRLINE", "MRO"}},
    "INSTALL": {"label": "Install on an aircraft", "roles": {"AIRLINE"}},
    "REMOVE": {"label": "Remove from the aircraft", "roles": {"AIRLINE"}},
    "USAGE": {"label": "Record flight cycles and hours", "roles": {"AIRLINE"}},
}

# A serial number: starts with a capital letter or digit, then 2-39 more letters, digits or hyphens (3-40 in total).
SERIAL_FORMAT = re.compile(r"^[A-Z0-9][A-Z0-9-]{2,39}$")
# A SHA-256 fingerprint: exactly 64 hexadecimal characters (0-9, a-f).
SHA256_FORMAT = re.compile(r"^[0-9a-f]{64}$")


class RuleBroken(Exception):
    """Raised when an action breaks a rule. `rule` is the rule's name, `message` explains it."""
    # Raising this means "STOP: this action is refused". The rule name (e.g. NOT_HOLDER) and the message
    # are shown in red on the dashboard.

    def __init__(self, rule: str, message: str):
        super().__init__(message)
        self.rule = rule
        self.message = message


def name(member: str) -> str:
    # Turn a member ID like "SKYLINK" into its full name, "SkyLink Airways", for messages.
    return MEMBERS.get(member, {}).get("name", member)


# ----------------------------------------------------------------------------- THE GUARD: check()
def check(action: str, member: str, data: dict, parts: dict) -> None:
    """Raise RuleBroken if the action is not allowed. Returning normally means: allowed."""
    # Rule: the action must exist.
    if action not in ACTIONS:
        raise RuleBroken("UNKNOWN_ACTION", f"There is no action called {action}.")
    # Rule ROLE: is this member's role allowed to do this action? (e.g. an airline cannot register a part)
    role = MEMBERS[member]["role"]
    if role not in ACTIONS[action]["roles"]:
        allowed = ", ".join(sorted(ACTIONS[action]["roles"]))
        raise RuleBroken("ROLE", f"A {role} cannot {ACTIONS[action]['label'].lower()}. Allowed: {allowed}.")

    serial = str(data.get("serial", "")).strip().upper()     # tidy the serial number: no spaces, capitals
    # ---- Rules for REGISTER (creating a new part: its "birth record")
    if action == "REGISTER":
        # Rule SERIAL_FORMAT: the serial number must look valid.
        if not SERIAL_FORMAT.match(serial):
            raise RuleBroken("SERIAL_FORMAT", "A serial number is 3-40 capital letters, digits or hyphens.")
        # Rule DUPLICATE_SERIAL: a serial number can exist only once (stops a forger cloning a real part).
        if serial in parts:
            raise RuleBroken("DUPLICATE_SERIAL", f"{serial} is already registered. A serial number can exist only once.")
        # Rule LIFE_LIMITS: the part needs positive life limits (max flight cycles and max flight hours).
        cycles, hours = data.get("max_cycles"), data.get("max_hours")
        if not (isinstance(cycles, int) and cycles > 0 and isinstance(hours, (int, float)) and hours > 0):
            raise RuleBroken("LIFE_LIMITS", "Both life limits (cycles and hours) must be positive numbers.")
        # Rule CERTIFICATE (optional): if a certificate fingerprint is given, it must be a real SHA-256 value.
        # Only this fingerprint goes on the chain; the PDF itself stays with the company.
        certificate = data.get("certificate")
        if certificate and not SHA256_FORMAT.match(certificate):
            raise RuleBroken("CERTIFICATE", "The certificate fingerprint must be a SHA-256 value (64 hex characters).")
        return                                                # all REGISTER rules passed: allowed

    # ---- Rules for every other action (the part must already exist)
    part = parts.get(serial)
    # Rule UNKNOWN_PART: a part with no birth record cannot be used (stops parts with no history).
    if part is None:
        raise RuleBroken("UNKNOWN_PART", f"{serial or 'This part'} has no birth record on the ledger, so it cannot be used.")
    # Rule RETIRED_FOREVER: a retired part is locked for everyone, forever. Checked before anything else.
    if part["state"] == "RETIRED":
        raise RuleBroken("RETIRED_FOREVER", f"SAFETY LOCK: {serial} is retired ({part['retired_reason']}). "
                                            "A retired part can never be used again.")
    # Rule NOT_HOLDER: only the member who currently holds the part may act on it.
    if part["holder"] != member:
        raise RuleBroken("NOT_HOLDER", f"{name(member)} does not hold {serial}; {name(part['holder'])} does.")

    if action == "TRANSFER":
        # Rule WRONG_STATE: you cannot hand over a part that is still fitted to an aircraft.
        if part["state"] != "IN_STOCK":
            raise RuleBroken("WRONG_STATE", f"{serial} is installed on {part['aircraft']}. Remove it before transferring it.")
        # Rule BAD_RECEIVER: the receiver must be another real member (and not the regulator).
        receiver = data.get("to")
        if receiver not in MEMBERS or receiver == member or MEMBERS[receiver]["role"] == "REGULATOR":
            raise RuleBroken("BAD_RECEIVER", "The receiver must be another member (not the regulator).")
    elif action == "INSTALL":
        # Rule WRONG_STATE: a part can be on only one aircraft at a time.
        if part["state"] != "IN_STOCK":
            raise RuleBroken("WRONG_STATE", f"{serial} is already installed on {part['aircraft']}.")
        if not str(data.get("aircraft", "")).strip():
            raise RuleBroken("AIRCRAFT_MISSING", "Enter the aircraft registration.")
    elif action == "REMOVE":
        # Rule WRONG_STATE: you can only remove a part that is installed.
        if part["state"] != "INSTALLED":
            raise RuleBroken("WRONG_STATE", f"{serial} is not installed on an aircraft.")
    elif action == "USAGE":
        # Rule WRONG_STATE: flights can only be recorded while the part is on an aircraft.
        if part["state"] != "INSTALLED":
            raise RuleBroken("WRONG_STATE", "Usage can only be recorded while the part is installed.")
        # Rule USAGE_NUMBERS: cycles must be a whole number and hours a number.
        # (True/False are refused on purpose: in Python, True counts as the number 1.)
        cycles, hours = data.get("cycles"), data.get("hours")
        if not (isinstance(cycles, int) and isinstance(hours, (int, float))) or isinstance(cycles, bool) or isinstance(hours, bool):
            raise RuleBroken("USAGE_NUMBERS", "Enter whole flight cycles and a number of flight hours.")
        # Rule USAGE_ONLY_UP: usage can never go down. This stops "clocking back" a part to make it look younger.
        if cycles < 0 or hours < 0:
            raise RuleBroken("USAGE_ONLY_UP", f"Usage can never go down (you entered {cycles:+,} cycles, {hours:+,} hours). "
                                              "Totals only ever increase.")
        if cycles == 0 and hours == 0:
            raise RuleBroken("USAGE_NUMBERS", "Enter some cycles or hours to add.")
    # Reaching the end without raising RuleBroken means: the action is ALLOWED.


# ----------------------------------------------------------------------------- THE BOOKKEEPER: apply()
def apply(action: str, member: str, data: dict, timestamp: str, block: int, parts: dict) -> str:
    """Change the parts after an action is committed. Returns a one-line summary."""
    # This only runs for actions that passed check() and are already in a block.
    serial = str(data.get("serial", "")).strip().upper()
    if action == "REGISTER":
        # Create the part's record: the maker holds it, it is in stock, and it has never flown.
        parts[serial] = {
            "serial": serial, "description": data.get("description", ""), "maker": member, "holder": member,
            "state": "IN_STOCK", "aircraft": None, "cycles": 0, "hours": 0.0,
            "max_cycles": data["max_cycles"], "max_hours": float(data["max_hours"]),      # its life limits
            "certificate": data.get("certificate") or None, "retired_reason": None, "history": [],  # certificate fingerprint
        }
        summary = f"Birth record by {name(member)}: limits {data['max_cycles']:,} cycles / {float(data['max_hours']):,.0f} hours"
    else:
        part = parts[serial]
        if action == "TRANSFER":
            summary = f"Transferred from {name(member)} to {name(data['to'])}"
            part["holder"] = data["to"]                                   # the receiver now holds the part
        elif action == "INSTALL":
            part["state"], part["aircraft"] = "INSTALLED", str(data["aircraft"]).strip().upper()   # fitted to an aircraft
            summary = f"Installed on {part['aircraft']} by {name(member)}"
        elif action == "REMOVE":
            summary = f"Removed from {part['aircraft']} by {name(member)}"
            part["state"], part["aircraft"] = "IN_STOCK", None            # back in stock
        else:  # USAGE
            part["cycles"] += data["cycles"]                              # add the new flights to the totals
            part["hours"] = round(part["hours"] + data["hours"], 1)
            summary = f"Usage +{data['cycles']:,} cycles / +{data['hours']:,} hours recorded by {name(member)}"
            # Has the part reached EITHER life limit (cycles or hours)?
            reached = [f"{part[k]:,} of {part['max_' + k]:,} {k}" for k in ("cycles", "hours") if part[k] >= part["max_" + k]]
            if reached:  # either limit reached: retire automatically, forever
                # Automatic retirement: nobody has to remember to do it. From now on, RETIRED_FOREVER
                # in check() refuses every action on this part.
                part["state"], part["aircraft"] = "RETIRED", None
                part["retired_reason"] = "life limit reached: " + " and ".join(reached)
                summary += f" - LIMIT REACHED, part automatically RETIRED ({' and '.join(reached)})"
    # Every action is added to the part's history (its "passport"), with the block it is stored in.
    parts[serial]["history"].append({"block": block, "action": action, "member": member,
                                     "timestamp": timestamp, "summary": summary})
    return summary


# ----------------------------------------------------------------------------- replay()
def replay(chain) -> dict:
    """Rebuild the current state of every part by re-applying every block from the start."""
    # Used when the app starts: there is no database. We start with no parts and re-apply every block
    # in order, so the current state always comes from the chain itself.
    parts: dict = {}
    for block in chain.blocks[1:]:          # skip block 0: it holds the network settings, not a part action
        for tx in block.transactions:
            apply(tx.action, tx.member, tx.data, tx.timestamp, block.index, parts)
    return parts

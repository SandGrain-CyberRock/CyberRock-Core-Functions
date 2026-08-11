#!/usr/bin/env python3
"""Prove each migrated example issues the same protocol calls as its original.

The 2026-08-10 restructure moved 27 demo scripts into use-case folders under
examples/. The rule for that move was: presentation may change, protocol
behaviour may not. This harness checks the second half mechanically.

For each old/new pair it extracts, in source order, every call that crosses a
boundary -- token.* (hardware) and cloud.* (HTTP) and config.* (setup) -- along
with each call's arguments rendered back to normalized source. Two files match
only if those sequences are identical.

Pure local helpers are deliberately NOT part of the sequence: they compute
values, they do not cross a boundary. They are still compared indirectly,
because they appear inside the arguments of the calls that do.

Normalized away (the three approved deviations):
  1. strToList(x)                     -> hex_to_bytes(x)
  2. the inline timestamp idiom       -> token.make_challenge()
  3. print() and __main__ guard       -> ignored entirely

What this proves:   no protocol call was added, dropped, reordered, or handed
                    a different value.
What it does NOT:   that the flows still work against real hardware. That
                    requires a token and credentials. Re-test before shipping.

Usage:
    python3 scripts/verify_migration.py

Exit 0 if every pair matches, 1 on a difference, 2 if the pre-restructure
scripts are not on disk to compare against (they live in
CyberRockCoreFunctions/ before archiving, .originals-<date>/ after).
"""
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NEW_DIR = ROOT / "examples"


def find_originals():
    """Locate the pre-restructure scripts.

    They live in CyberRockCoreFunctions/ before the migration and in
    .originals-<date>/ after it has been archived. Returns None if neither
    is present, in which case there is nothing to compare against.
    """
    candidates = [ROOT / "CyberRockCoreFunctions"]
    candidates += sorted(ROOT.glob(".originals-*"), reverse=True)
    for c in candidates:
        if c.is_dir():
            return c
    return None


OLD_DIR = find_originals()

# The canonical map -- must stay in sync with the plan's name table.
NAME_MAP = {
    "token_id.py": "01-getting-started/token_id.py",
    "bist.py": "01-getting-started/bist.py",
    "token_claim.py": "01-getting-started/token_claim.py",
    "token_auth.py": "02-prove-device-identity/token_auth.py",
    "host_auth.py": "02-prove-device-identity/host_auth.py",
    "host_auth_priority.py": "02-prove-device-identity/host_auth_priority.py",
    "host_auth_hrwrequest.py": "02-prove-device-identity/host_auth_hrwrequest.py",
    "mutual_auth.py": "02-prove-device-identity/mutual_auth.py",
    "mutual_auth_host.py": "02-prove-device-identity/mutual_auth_host.py",
    "token_auth_ek.py": "03-derive-session-key/token_auth_ek.py",
    "token_auth_ek_rsa2048.py": "03-derive-session-key/token_auth_ek_rsa2048.py",
    "host_auth_ek.py": "03-derive-session-key/host_auth_ek.py",
    "host_auth_ek_rsa2048.py": "03-derive-session-key/host_auth_ek_rsa2048.py",
    "host_auth_ek_priority.py": "03-derive-session-key/host_auth_ek_priority.py",
    "host_auth_ek_priority_rsa2048.py":
        "03-derive-session-key/host_auth_ek_priority_rsa2048.py",
    "hrwrequest.py": "04-sign-and-verify-data/hrwrequest.py",
    "hrwrequest_priority.py": "04-sign-and-verify-data/hrwrequest_priority.py",
    "hrwrequest_ek.py": "04-sign-and-verify-data/hrwrequest_ek.py",
    "hrwrequest_ek_priority.py": "04-sign-and-verify-data/hrwrequest_ek_priority.py",
    "hrwrequest_ek_rsa2048.py": "04-sign-and-verify-data/hrwrequest_ek_rsa2048.py",
    "hrwrequest_ek_priority_rsa2048.py":
        "04-sign-and-verify-data/hrwrequest_ek_priority_rsa2048.py",
    "secureboot.py": "05-attest-boot-chain/secureboot.py",
    "secureboot_host.py": "05-attest-boot-chain/secureboot_host.py",
    "secureboot_hrw.py": "05-attest-boot-chain/secureboot_hrw.py",
    "daisychain.py": "06-chain-multiple-items/daisychain.py",
    "daisychain_host.py": "06-chain-multiple-items/daisychain_host.py",
    "daisychain_hrw.py": "06-chain-multiple-items/daisychain_hrw.py",
}

# Calls whose root name means "this crosses a boundary".
TRACKED_ROOTS = {"token", "cloud", "config"}

# Pure local computation -- excluded from the sequence, still compared as
# arguments to the calls that consume them.
PURE_HELPERS = {
    "strToList", "hex_to_bytes", "token.hex_to_bytes",
    "make_challenge", "token.make_challenge",
    "listToInt", "intToList", "list_invert", "token.list_invert",
}

# Source-level rewrites applied before comparison, so the approved renames
# do not read as drift.
SOURCE_ALIASES = (
    ("token.hex_to_bytes", "hex_to_bytes"),
    ("strToList", "hex_to_bytes"),
    ("token.make_challenge", "make_challenge"),
)


def _dotted(node):
    """Render a call target as a dotted name, or None if it is not one."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _normalize(text):
    for old, new in SOURCE_ALIASES:
        text = text.replace(old, new)
    return " ".join(text.split())


def call_sequence(path):
    """Ordered protocol calls in a file as [(name, (arg_src, ...))].

    Source order, not AST-walk order: nested calls are disambiguated by
    (line, column) so the same nesting produces the same order in both files.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    calls.sort(key=lambda n: (n.lineno, n.col_offset))

    out = []
    for node in calls:
        name = _dotted(node.func)
        if name is None or name in PURE_HELPERS:
            continue
        if name.split(".")[0] not in TRACKED_ROOTS:
            continue
        args = tuple(_normalize(ast.unparse(a)) for a in node.args)
        kwargs = tuple(
            f"{k.arg}={_normalize(ast.unparse(k.value))}" for k in node.keywords
        )
        out.append((_normalize(name), args + kwargs))
    return out


def _describe(entry):
    if entry is None:
        return "<absent>"
    name, args = entry
    return f"{name}({', '.join(args)})"


def main():
    if len(NAME_MAP) != 27:
        print(f"FAIL: name map has {len(NAME_MAP)} entries, expected 27")
        return 1

    if OLD_DIR is None:
        print("SKIP: no pre-restructure scripts to compare against.\n")
        print("  Looked for:  CyberRockCoreFunctions/   (before archiving)")
        print("               .originals-*/             (after archiving)\n")
        print("  This is expected once the originals have been deleted. Until then,")
        print("  keep the archive in place so this check can be re-run.")
        return 2

    print(f"Comparing examples/ against {OLD_DIR.name}/\n")
    failures, compared = [], 0

    for old_name, new_rel in sorted(NAME_MAP.items(), key=lambda kv: kv[1]):
        old_path, new_path = OLD_DIR / old_name, NEW_DIR / new_rel

        if not old_path.exists():
            failures.append(f"{old_name}: original missing")
            print(f"  ????  {old_name:38s} original missing")
            continue
        if not new_path.exists():
            failures.append(f"{new_rel}: not migrated yet")
            print(f"  ....  {old_name:38s} -> not migrated yet")
            continue

        old_seq, new_seq = call_sequence(old_path), call_sequence(new_path)
        compared += 1

        if old_seq == new_seq:
            print(f"  ok    {old_name:38s} -> {new_rel}  ({len(old_seq)} calls)")
            continue

        failures.append(f"{old_name} -> {new_rel}: call sequence differs")
        print(f"  DIFF  {old_name:38s} -> {new_rel}")
        for i in range(max(len(old_seq), len(new_seq))):
            a = old_seq[i] if i < len(old_seq) else None
            b = new_seq[i] if i < len(new_seq) else None
            if a != b:
                print(f"          [{i}] old: {_describe(a)}")
                print(f"          [{i}] new: {_describe(b)}")

    print(f"\n{compared}/27 pairs compared, {len(failures)} failure(s)")
    for f in failures:
        print(f"  - {f}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

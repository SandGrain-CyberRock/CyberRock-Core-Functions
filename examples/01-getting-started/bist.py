"""
Run the token's Built-In Self-Test (BIST).

WHEN TO USE   Second script on a new setup, and the first thing to run when
              a flow starts failing -- it separates "the token is faulty"
              from "the cloud rejected us".
YOU NEED      A connected token. No credentials, no network.
THIS PROVES   Basic:  the token's own hardware self-test passes.
              --full: the TID, RW and EK it reports under BIST agree with
                      what the normal command path returns.
COST          Basic 2 token transfers, --full 4. 0 cloud calls.

Usage:
    python examples/01-getting-started/bist.py          # basic check
    python examples/01-getting-started/bist.py --full   # full verification
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import CyberRock_Token as token
import CyberRock_Config as config


def list_invert(l):
    """Bitwise-invert every byte. The EK check challenges with an inverted TID."""
    return [(~e) & 0xFF for e in l]


def main():
    parser = argparse.ArgumentParser(description="CyberRock Token Built-In Self-Test")
    parser.add_argument("--full", action="store_true",
                        help="Run full verification (TID, RW, EK consistency checks)")
    args = parser.parse_args()

    # 1. CONFIGURE -- interface (SPI/USB) and environment come from CyberRock_Config
    config.init()

    # 2. CONNECT -- read TID via the standard identification command
    tid = token.get_tid()
    print('TID: ' + tid + '\n')

    # 3. RUN THE FLOW -- the token's built-in self-test
    b_pass, l_pcc, l_id, l_rw, l_ek = token.do_bist()

    # Check 1: BIST hardware pass/fail
    if b_pass == 1:
        print('BIST passed')
    else:
        print('BIST failed')
        sys.exit(1)

    if not args.full:
        return

    # --- Full verification below ---
    # BIST reports the TID, RW and EK it computed internally. Each is
    # re-derived through the normal command path and compared.
    l_tid = l_pcc + l_id
    allchecks = True

    # Check 2: TID consistency
    bist_tid = ''.join('%02x' % e for e in l_tid)
    if bist_tid == tid:
        print('TID check passed')
    else:
        print('TID check failed')
        allchecks = False

    # Check 3: RW consistency (token auth with TID as challenge)
    rw = token.do_token_auth(l_tid)
    bist_rw = ''.join('%02x' % e for e in l_rw)
    if bist_rw == rw:
        print('RW check passed')
    else:
        print('RW check failed')
        allchecks = False

    # Check 4: EK consistency (host auth EK with inverted TID as challenge)
    rw2, ek = token.do_host_auth_ek(list_invert(l_tid))
    bist_ek = ''.join('%02x' % e for e in l_ek)
    if bist_ek == ek:
        print('EK check passed')
    else:
        print('EK check failed')
        allchecks = False

    # 4. ┌─ YOUR INTEGRATION POINT ──────────────────────────────────────┐
    #    │ A non-zero exit status means the token failed self-test.      │
    #    │ Gate your provisioning or boot sequence on it.                │
    #    └───────────────────────────────────────────────────────────────┘
    if allchecks:
        print('\nAll checks passed!')
    else:
        print('\nSome checks failed.')
        sys.exit(1)


if __name__ == "__main__":
    main()

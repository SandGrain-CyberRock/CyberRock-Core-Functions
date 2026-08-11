"""
Read the token's unique identity (TID).

WHEN TO USE   The first script to run on a new setup. It confirms wiring,
              driver and interface configuration before any credential or
              network problem can confuse the picture.
YOU NEED      A connected token. No credentials, no network.
THIS PROVES   The host can talk to the token over SPI or USB.
COST          1 token transfer, 0 cloud calls.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import CyberRock_Token as token
import CyberRock_Config as config


def main():
    # 1. CONFIGURE -- interface (SPI/USB) and environment come from CyberRock_Config
    config.init()

    # 2. CONNECT -- read the token's 32-byte identity
    tid = token.get_tid()

    # 3. ┌─ YOUR INTEGRATION POINT ──────────────────────────────────────┐
    #    │ `tid` is a 64-character hex string that uniquely identifies   │
    #    │ this token. Every other example starts by reading it, and     │
    #    │ every cloud call is scoped to it.                             │
    #    └───────────────────────────────────────────────────────────────┘
    print('TID: ' + tid + '\n')


if __name__ == "__main__":
    main()

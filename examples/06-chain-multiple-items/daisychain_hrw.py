"""
Ask the cloud what a chain's final value *should* be.

WHEN TO USE   Provisioning and diagnostics. Rather than submitting a value
              for a yes/no verdict, you ask the cloud to derive the expected
              final HRW for a given chain -- useful for recording a
              known-good reference, or for locating which link of a failing
              chain diverged.
YOU NEED      A connected token, IoT device credentials, network access.
THIS PROVES   The locally walked chain matches the cloud's independent
              derivation for the same (TIDs, data, ChainCW).
COST          3 cloud calls (the last one polls), 6 token transfers.

Five TIDs and four data items here -- the chain length is yours to choose,
and this file shows the correct advancing loop.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import CyberRock_Cloud as cloud
import CyberRock_Token as token
import CyberRock_Config as config
import SandGrain_Credentials as credentials


def main():

    # 1. CONFIGURE -- interface (SPI/USB) and environment come from CyberRock_Config
    config.init()

    # 2. CONNECT -- read the token's identity
    tid = token.get_tid()
    print(f"TID: {tid}")

    # 3. RUN THE FLOW
    # Chain structure: 5 TIDs (same token), 4 data items
    l_tid = [tid, tid, tid, tid, tid]
    l_data = ['ffffffffffffffffffffffffffffff01', 'ffffffffffffffffffffffffffffff02', 'ffffffffffffffffffffffffffffff03', 'ffffffffffffffffffffffffffffff04']

    # The device picks the starting value itself.
    # NOTE: make_challenge() has one-second granularity. See docs/known-issues.md.
    chain_cw = token.make_challenge()

    print(f"ChainCW: {chain_cw}")

    # Walk the chain locally -- note `hrw` is reassigned each pass, so the
    # chain advances correctly.
    hrw = token.do_host_auth(token.hex_to_bytes(chain_cw))
    for d in l_data:
        hcw_next = hrw + d
        hrw = token.do_host_auth(token.hex_to_bytes(hcw_next))

    hrw_local = hrw
    print(f"HRW (local chain): {hrw_local}")

    iotaccesstoken, iotid = cloud.do_device_login(
        credentials.cloudflaretokens, credentials.iotusername, credentials.iotpassword, False)

    # Request cloud to compute the expected chain HRW
    transactionid = cloud.do_device_requestDaisyChainHRW(
        credentials.cloudflaretokens, iotaccesstoken,
        l_tid, l_data, chain_cw, False, False)

    # Poll for result
    hrw_cloud = cloud.do_device_checkRequestDaisyChainHRWStatus(
        credentials.cloudflaretokens, iotaccesstoken, transactionid, False, False)

    print(f"HRW (cloud chain): {hrw_cloud}")

    # 4. ┌─ YOUR INTEGRATION POINT ──────────────────────────────────────┐
    #    │ `hrw_cloud` is the reference value for this chain. Record it  │
    #    │ at provisioning time and compare against it later.            │
    #    └───────────────────────────────────────────────────────────────┘
    if hrw_local == hrw_cloud:
        print("\nDaisy Chain HRW verified — chain is authentic")
    else:
        print("\nDaisy Chain HRW mismatch!")


if __name__ == "__main__":
    main()

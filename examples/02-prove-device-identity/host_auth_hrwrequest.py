"""
Prove a device is genuine, then ask the cloud to recompute the same HRW.

WHEN TO USE   Diagnostics and integration bring-up. Running the two halves
              back to back tells you whether a failure is in the token, the
              challenge handling, or the verification -- because you get the
              cloud's own answer for the same HCW alongside the token's.
YOU NEED      A connected token, IoT device credentials, network access.
THIS PROVES   Authentication succeeded AND the HRW the cloud derives for this
              (TID, HCW) matches what the token produced.
COST          5 cloud calls (two of them poll), 2 token transfers.
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
    print(tid)

    # 3. RUN THE FLOW
    # The host picks its own challenge. NOTE: make_challenge() has one-second
    # granularity -- use a random nonce in production. See docs/known-issues.md.
    hcw = token.make_challenge()

    iotaccesstoken, iotid = cloud.do_device_login(
        credentials.cloudflaretokens, credentials.iotusername, credentials.iotpassword)

    # Part 1 -- authenticate using the token's HRW
    hrw = token.do_host_auth(token.hex_to_bytes(hcw))
    print(f"HRW: {hrw}")

    transactionid = cloud.do_device_hostauth_request(
        credentials.cloudflaretokens, iotaccesstoken, tid, hcw, hrw, False)

    authenticationresult, claimid = cloud.do_device_hostauth_checkstatus(
        credentials.cloudflaretokens, iotaccesstoken, transactionid, False)

    print(f"\nAuth result: {authenticationresult}")

    # Part 2 -- ask the cloud to derive the HRW for the same challenge
    HRW2transactionID = cloud.do_device_requestHRW(
        credentials.cloudflaretokens, iotaccesstoken, tid, hcw)

    result, hrwreq = cloud.do_device_requestHRWstatus(
        credentials.cloudflaretokens, iotaccesstoken, HRW2transactionID)

    print(result)
    print(f"HRW: {hrwreq}")

    # 4. ┌─ YOUR INTEGRATION POINT ──────────────────────────────────────┐
    #    │ `hrw` came from the token, `hrwreq` from the cloud. Equal     │
    #    │ values mean both sides agree on the shared secret.            │
    #    └───────────────────────────────────────────────────────────────┘


if __name__ == "__main__":
    main()

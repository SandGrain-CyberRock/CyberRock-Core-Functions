"""
Prove a device is genuine -- device issues the challenge.

WHEN TO USE   The device decides when to prove itself (on boot, on reconnect,
              before a privileged operation). No cloud round-trip is needed to
              obtain a challenge, so the token work can happen offline and be
              submitted later.
YOU NEED      A connected token, IoT device credentials, network access.
THIS PROVES   The token turned a host-generated challenge (HCW) into the
              host response word (HRW) the cloud independently expects.
COST          3 cloud calls (the last one polls), 2 token transfers.

Asynchronous: the result is collected by polling. For an immediate answer in
a single call, see host_auth_priority.py.
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

    # Only the genuine token can turn HCW into HRW
    hrw = token.do_host_auth(token.hex_to_bytes(hcw))
    print(f"HRW: {hrw}")

    # Submit the pair and poll for the verdict
    transactionid = cloud.do_device_hostauth_request(
        credentials.cloudflaretokens, iotaccesstoken, tid, hcw, hrw, False)

    authenticationresult, claimid = cloud.do_device_hostauth_checkstatus(
        credentials.cloudflaretokens, iotaccesstoken, transactionid, False)

    # 4. ┌─ YOUR INTEGRATION POINT ──────────────────────────────────────┐
    #    │ AUTH_OK  -> the device is genuine, proceed.                   │
    #    │ CLAIM_TOKEN -> genuine but unclaimed, see token_claim.py.     │
    #    │ anything else -> reject.                                      │
    #    └───────────────────────────────────────────────────────────────┘
    print(f"\nAuth result: {authenticationresult}")


if __name__ == "__main__":
    main()

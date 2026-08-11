"""
Derive a shared session key (EK) -- device issues the challenge.

WHEN TO USE   The device drives key establishment on its own schedule (on
              boot, on session start) rather than waiting for the cloud to
              challenge it.
YOU NEED      A connected token, IoT device credentials, network access.
THIS PROVES   The token authenticated AND both sides independently derived
              the same 16-byte Ephemeral Key.
COST          3 cloud calls (the last one polls), 2 token transfers.

Asynchronous. For an immediate answer see host_auth_ek_priority.py.
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
    # The host picks its own challenge. NOTE: make_challenge() has one-second
    # granularity -- use a random nonce in production. See docs/known-issues.md.
    hcw = token.make_challenge()

    # The token returns both the response AND its derived key
    hrw, ek_token = token.do_host_auth_ek(token.hex_to_bytes(hcw))
    print(f"HRW: {hrw}")
    print(f"EK (token): {ek_token}")

    iotaccesstoken, iotid = cloud.do_device_login(
        credentials.cloudflaretokens, credentials.iotusername, credentials.iotpassword, False)

    # Submit host auth (EK variant, async)
    transactionid = cloud.do_device_hostauthEK_request(
        credentials.cloudflaretokens, iotaccesstoken, tid, hcw, hrw, False)

    # Poll for the verdict and the cloud's own derivation of the key
    authenticationresult, claimid, ek_cloud = cloud.do_device_hostauthEK_checkstatus(
        credentials.cloudflaretokens, iotaccesstoken, transactionid, False)

    print(f"\nAuth result: {authenticationresult}")
    print(f"EK (token):  {ek_token}")
    print(f"EK (cloud):  {ek_cloud}")

    # 4. ┌─ YOUR INTEGRATION POINT ──────────────────────────────────────┐
    #    │ Use `ek_token` as your session key only once it matches       │
    #    │ `ek_cloud`. A mismatch means the two sides disagree.          │
    #    └───────────────────────────────────────────────────────────────┘
    if ek_token == ek_cloud:
        print("\nEphemeral keys match — shared session key established")
    else:
        print("\nEphemeral key mismatch!")


if __name__ == "__main__":
    main()

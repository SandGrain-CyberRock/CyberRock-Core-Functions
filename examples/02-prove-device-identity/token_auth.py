"""
Prove a device is genuine -- cloud issues the challenge.

WHEN TO USE   The cloud decides when to challenge the device. Use this when
              verification is driven server-side (a periodic re-attestation,
              an admin-triggered check) rather than by the device itself.
YOU NEED      A connected token, IoT device credentials, network access.
THIS PROVES   The token holds the secret the CyberRock HSM expects for this
              TID: it turned the cloud's challenge word (CW) into the
              response word (RW) only the real token could produce.
COST          4 cloud calls (the last one polls), 2 token transfers.

Asynchronous: replyRW returns immediately and the result is collected by
polling checkAuthStatus. For a single-call variant see host_auth_priority.py.
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
    iotaccesstoken, iotid = cloud.do_device_login(
        credentials.cloudflaretokens, credentials.iotusername, credentials.iotpassword)

    # Step 1: ask the cloud for a challenge word
    cw, transactionid = cloud.do_device_tokenauth_requestcw(
        credentials.cloudflaretokens, iotaccesstoken, tid, False)

    # Step 2: only the genuine token can turn CW into RW
    rw = token.do_token_auth(token.hex_to_bytes(cw))

    # Step 3: hand the response back
    transactionidresponse = cloud.do_device_tokenauth_replyrw(
        credentials.cloudflaretokens, iotaccesstoken, tid, cw, rw, transactionid, False)

    # Step 4: poll until the cloud reaches a verdict
    authenticationresult, claimid = cloud.do_device_tokenauth_checkstatus(
        credentials.cloudflaretokens, iotaccesstoken, transactionid, False)

    # 4. ┌─ YOUR INTEGRATION POINT ──────────────────────────────────────┐
    #    │ AUTH_OK  -> the device is genuine, proceed.                   │
    #    │ CLAIM_TOKEN -> genuine but unclaimed, see token_claim.py.     │
    #    │ anything else -> reject.                                      │
    #    └───────────────────────────────────────────────────────────────┘
    print(f"\nAuth result: {authenticationresult}")


if __name__ == "__main__":
    main()

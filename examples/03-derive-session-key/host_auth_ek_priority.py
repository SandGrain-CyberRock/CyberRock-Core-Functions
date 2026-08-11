"""
Derive a shared session key (EK) -- device issues the challenge, immediate result.

WHEN TO USE   The common case for session-key establishment. One request,
              one answer carrying both the verdict and the key. Start here
              unless you specifically need the async variant.
YOU NEED      A connected token, IoT device credentials, network access.
THIS PROVES   The token authenticated AND both sides independently derived
              the same 16-byte Ephemeral Key.
COST          2 cloud calls, 2 token transfers.

Synchronous (priority). The EK travels over HTTPS in plaintext here; for
end-to-end confidentiality see host_auth_ek_priority_rsa2048.py.
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

    # Submit and receive the verdict + key in the same call
    authenticationresult, ek_cloud = cloud.do_device_EKpriorityhostauth(
        credentials.cloudflaretokens, iotaccesstoken, tid, hcw, hrw, False)

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

"""
Produce a hardware-backed MAC over your own data -- immediate cloud confirmation.

WHEN TO USE   The common case for tagging data. One request, one answer.
              Feed your own 32-byte value in as the challenge (HCW) instead
              of the timestamp used here; the resulting HRW is the tag.
YOU NEED      A connected token, IoT device credentials, network access.
THIS PROVES   The cloud independently derived the same HRW for this
              (TID, HCW) pair -- so a verifier can check the tag without ever
              holding the token.
COST          2 cloud calls, 2 token transfers.

Synchronous (priority). Compare hrwrequest.py for the polling variant.
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
    # Substitute your own 64-hex-char value here to tag real data.
    # NOTE: make_challenge() has one-second granularity. See docs/known-issues.md.
    hcw = token.make_challenge()

    # Tag it in hardware
    hrw_token = token.do_host_auth(token.hex_to_bytes(hcw))
    print(f"HRW (token): {hrw_token}")

    iotaccesstoken, iotid = cloud.do_device_login(
        credentials.cloudflaretokens, credentials.iotusername, credentials.iotpassword, False)

    # Ask the cloud to derive the same tag (priority / synchronous)
    result, hrw_cloud = cloud.do_device_priorityrequestHRW(
        credentials.cloudflaretokens, iotaccesstoken, tid, hcw, False)

    print(f"HRW (cloud): {hrw_cloud}")
    print(f"Status: {result}")

    # 4. ┌─ YOUR INTEGRATION POINT ──────────────────────────────────────┐
    #    │ Equal values mean the tag verifies. Store `hrw_token`         │
    #    │ alongside your data as the hardware-anchored signature.       │
    #    └───────────────────────────────────────────────────────────────┘
    if hrw_token == hrw_cloud:
        print("\nHRW values match — cloud authenticated")
    else:
        print("\nHRW mismatch!")


if __name__ == "__main__":
    main()

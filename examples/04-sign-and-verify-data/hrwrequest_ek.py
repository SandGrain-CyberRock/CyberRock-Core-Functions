"""
Tag data AND derive a session key in one exchange.

WHEN TO USE   You need both a hardware-backed tag over your data and a
              symmetric key for the session that follows -- one round-trip
              instead of two separate flows.
YOU NEED      A connected token, IoT device credentials, network access.
THIS PROVES   The cloud independently derived the same HRW *and* the same
              Ephemeral Key for this (TID, HCW) pair.
COST          3 cloud calls (the last one polls), 2 token transfers.

Asynchronous. For an immediate answer see hrwrequest_ek_priority.py.
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

    # The token returns both the tag AND its derived key
    hrw_token, ek_token = token.do_host_auth_ek(token.hex_to_bytes(hcw))
    print(f"HRW (token): {hrw_token}")
    print(f"EK  (token): {ek_token}")

    iotaccesstoken, iotid = cloud.do_device_login(
        credentials.cloudflaretokens, credentials.iotusername, credentials.iotpassword, False)

    # Ask the cloud for both (async: request + poll)
    transactionid = cloud.do_device_EKrequestHRW(
        credentials.cloudflaretokens, iotaccesstoken, tid, hcw, False)

    result, hrw_cloud, ek_cloud = cloud.do_device_EKrequestHRWstatus(
        credentials.cloudflaretokens, iotaccesstoken, transactionid, False)

    print(f"\nStatus: {result}")
    print(f"HRW (cloud): {hrw_cloud}")
    print(f"EK  (cloud): {ek_cloud}")

    # 4. ┌─ YOUR INTEGRATION POINT ──────────────────────────────────────┐
    #    │ BOTH must match before you trust either value.                │
    #    └───────────────────────────────────────────────────────────────┘
    if hrw_token == hrw_cloud and ek_token == ek_cloud:
        print("\nHRW and EK match")
    else:
        print("\nMismatch!")


if __name__ == "__main__":
    main()

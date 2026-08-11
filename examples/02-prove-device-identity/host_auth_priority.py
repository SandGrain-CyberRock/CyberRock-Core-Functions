"""
Prove a device is genuine -- device issues the challenge, immediate result.

WHEN TO USE   The common case. The device has network and needs a yes/no
              before it can continue. One request, one answer, no polling.
              Start here unless you specifically need the async variant.
YOU NEED      A connected token, IoT device credentials, network access.
THIS PROVES   The token turned a host-generated challenge (HCW) into the
              host response word (HRW) the cloud independently expects.
COST          2 cloud calls, 2 token transfers.

Synchronous (priority): the verdict arrives in the same call that submits
the proof. Compare host_auth.py for the polling variant.
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

    # Only the genuine token can turn HCW into HRW
    hrw = token.do_host_auth(token.hex_to_bytes(hcw))
    print(f"HRW: {hrw}")

    iotaccesstoken, iotid = cloud.do_device_login(
        credentials.cloudflaretokens, credentials.iotusername, credentials.iotpassword, False)

    # Submit (TID, HCW, HRW) and get the verdict in the same call
    result = cloud.do_device_priorityhostauth(
        credentials.cloudflaretokens, iotaccesstoken, tid, hcw, hrw, False)

    print(f"\nAuth result: {result}")

    # 4. ┌─ YOUR INTEGRATION POINT ──────────────────────────────────────┐
    #    │ Replace this block with your own logic. `result` is           │
    #    │ 'AUTH_OK' on success, or an error status.                     │
    #    └───────────────────────────────────────────────────────────────┘
    if result == 'AUTH_OK':
        print("Priority Host Authentication successful")
    else:
        print("Priority Host Authentication failed!")


if __name__ == "__main__":
    main()
